use {
    ffmpeg::{
        codec::Context as Codec,
        format::{context::Input as MediaStream, Input as MediaFormat},
        media::Type as MediaType,
        software::scaling::{Context as Scaler, Flags as ScalerFlags},
        sys,
        util::{format::Pixel as PixelFormat, frame::Video as VideoFrame},
    },
    futures_util::TryStreamExt,
    image::{Delay, Frame, RgbaImage},
    std::{
        ffi, fmt,
        io::{self, BufReader, Read},
        mem::{self, ManuallyDrop, MaybeUninit},
        ops::{Deref, DerefMut},
        ptr::{self, NonNull},
        slice,
        time::Duration,
    },
    tokio::{sync::mpsc, task},
    tokio_util::io::SyncIoBridge,
};

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type Result<T> = std::result::Result<T, Error>;

const BUF_SIZE: usize = 4096 * 8;

#[tokio::main]
async fn main() -> Result<()> {
    //tracing_subscriber::fmt::init();

    /*let client = reqwest::Client::new();
    let response = client
        .get("https://media.tenor.com/xFyrOvthJIEAAAPo/wombat-cute.mp4")
        .send()
        .await?;

    response
        .headers()
        .get(reqwest::header::ACCEPT_RANGES)
        .unwrap();

    response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .unwrap();

    let stream = response.bytes_stream().map_err(io::Error::other);
    let mut stream = BufReader::new(SyncIoBridge::new(StreamReader::new(stream)));*/

    let mut stream = BufReader::new(SyncIoBridge::new(
        tokio::fs::File::open("wombat.mp4").await?,
    ));

    let (sender, mut receiver) = mpsc::unbounded_channel();

    let task = task::spawn_blocking(move || -> io::Result<()> {
        // Initial buffer for guessing the format of a stream.
        let mut init_buf = Vec::with_capacity(BUF_SIZE);

        // FIXME: Replace with `read_buf` when it's stable.
        // SAFETY: This is only reading into `init_buf`.
        unsafe {
            stream.read_exact(mem::transmute::<&mut [MaybeUninit<u8>], &mut [u8]>(
                init_buf.spare_capacity_mut(),
            ))?;

            init_buf.set_len(BUF_SIZE);
        }

        // Create a new stream.
        let mut input = NonNull::new(unsafe { sys::avformat_alloc_context() })
            .map(|ptr| unsafe { MediaStream::wrap(ptr.as_ptr()) })
            .ok_or_else(|| io::Error::other("Unable to create a new stream"))?;

        // Create an FFmpeg buffer for guessing the format of a stream, includes padding as
        // required by `av_probe_input_format`.
        let mut guess_buf = Buffer::alloc(BUF_SIZE as ffi::c_int + sys::AVPROBE_PADDING_SIZE)?;

        // Copy our initial buffer into it.
        guess_buf[..BUF_SIZE].copy_from_slice(&init_buf);

        let probe_data = sys::AVProbeData {
            filename: c"stream".as_ptr(),
            buf: guess_buf.as_ptr().cast_mut(),
            buf_size: guess_buf.len,
            mime_type: ptr::null(),
        };

        // Now, guess the format.
        let media_format =
            NonNull::new(unsafe { sys::av_probe_input_format(&probe_data, 1).cast_mut() })
                .or_else(|| {
                    NonNull::new(unsafe { sys::av_probe_input_format(&probe_data, 0).cast_mut() })
                })
                .map(|ptr| unsafe { MediaFormat::wrap(ptr.as_ptr()) })
                .ok_or_else(|| io::Error::other("Unable to determine format of stream"))?;

        // `guess_buf` is freed by `MediaFormat` on drop.
        let _guess_buf = ManuallyDrop::new(guess_buf);

        // Create an FFmpeg buffer for I/O.
        let io_buf = Buffer::alloc(BUF_SIZE as ffi::c_int)?;

        // Chain our initial buffer with the rest of the stream, move it into a type-erased box, box
        // the box, and convert the outer box to a raw pointer to be used within FFmpeg's I/O.
        let opaque: *mut Box<dyn Read> = Box::into_raw(Box::new(Box::new(init_buf.chain(stream))));

        // Create an FFmpeg I/O context.
        let io_context = NonNull::new(unsafe {
            sys::avio_alloc_context(
                io_buf.ptr.as_ptr(),
                io_buf.len,
                0,
                opaque.cast::<ffi::c_void>(),
                Some(read),
                None,
                None,
            )
        })
        .ok_or_else(|| io::Error::other("Unable to allocate FFmpeg I/O context"))?;

        // `io_buf` is freed by `MediaStream` on drop.
        let _io_buf = ManuallyDrop::new(io_buf);

        unsafe {
            // Set the FFmpeg I/O context on the media stream.
            (*input.as_mut_ptr()).pb = io_context.as_ptr();
        }

        // Open the stream.
        let result = unsafe {
            sys::avformat_open_input(
                &mut input.as_mut_ptr(),
                ptr::null(),
                media_format.as_ptr(),
                ptr::null_mut(),
            )
        };

        if result != 0 {
            return Err(to_io(ffmpeg::Error::from(result)));
        }

        // Find the best video stream.
        let stream = input
            .streams()
            .best(MediaType::Video)
            .ok_or(ffmpeg::Error::StreamNotFound)
            .map_err(to_io)?;

        // Get the video stream index.
        let index = stream.index();

        // Create a video decoder.
        let mut decoder = Codec::from_parameters(stream.parameters())
            .map_err(to_io)?
            .decoder()
            .video()
            .map_err(to_io)?;

        let mut last_timestamp: u32 = 0;

        let iter = input
            .packets()
            .filter(|(stream, _packet)| stream.index() == index)
            .map(|(_stream, packet)| packet);

        for packet in iter {
            decoder.send_packet(&packet).map_err(to_io)?;

            let mut input = VideoFrame::empty();
            let mut output = VideoFrame::empty();

            decoder.receive_frame(&mut input).map_err(to_io)?;

            Scaler::get(
                input.format(),
                input.width(),
                input.height(),
                PixelFormat::RGBA,
                input.width(),
                input.height(),
                ScalerFlags::FAST_BILINEAR,
            )
            .map_err(to_io)?
            .run(&input, &mut output)
            .map_err(to_io)?;

            let image =
                RgbaImage::from_raw(output.width(), output.height(), output.data(0).to_vec())
                    .unwrap();

            let timestamp = input
                .timestamp()
                .map(|timestamp| timestamp as u32)
                .unwrap_or_else(|| last_timestamp.saturating_add(1));

            let delay = Delay::from_numer_denom_ms(timestamp, 16);

            last_timestamp = timestamp;

            let frame = Frame::from_parts(image, 0, 0, delay);

            let (numer, denom) = delay.numer_denom_ms();

            //println!("{:?}", Duration::from_millis(numer as u64 / denom as u64));
            //println!("{}x{}", frame.buffer().width(), frame.buffer().height());

            let mut bytes = io::Cursor::new(Vec::with_capacity(8192));

            image::DynamicImage::from(frame.into_buffer())
                .write_to(&mut bytes, image::ImageFormat::Png)
                .unwrap();

            use base64::engine::Engine;

            let mut string = String::with_capacity(8192);

            base64::engine::general_purpose::STANDARD.encode_string(bytes.get_ref(), &mut string);

            sender.send(format!("\x1b]1337;File=inline=1;:{string}\x07"));
        }

        Ok(())
    });

    let render = task::spawn_blocking(move || -> io::Result<()> {
        let mut i = 0;
        let mut then = std::time::Instant::now();

        while let Some(code) = receiver.blocking_recv() {
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(then);

            if elapsed < Duration::from_millis(150) {
                println!("{code} {i}");
            } else {
                println!("{i} dropped");
            }

            then = now;
            i += 1;
        }

        Ok(())
    });

    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    Ok(())
}

fn to_io(error: ffmpeg::Error) -> io::Error {
    match error {
        ffmpeg::Error::Other { errno } => io::Error::from_raw_os_error(errno),
        error => io::Error::other(error),
    }
}

fn to_ffmpeg(error: io::Error) -> ffmpeg::Error {
    error
        .raw_os_error()
        .map(|errno| ffmpeg::Error::Other { errno })
        .unwrap_or(ffmpeg::Error::Eof)
}

unsafe extern "C" fn read(opaque: *mut ffi::c_void, data: *mut u8, len: ffi::c_int) -> ffi::c_int {
    let reader = &mut *opaque.cast::<Box<dyn Read>>();
    let buf = slice::from_raw_parts_mut(data, len as usize);

    match dbg!(reader.read(buf)) {
        Ok(0) => ffmpeg::Error::Eof.into(),
        Ok(len) => len as ffi::c_int,
        Err(error) => to_ffmpeg(error).into(),
    }
}

struct Buffer {
    ptr: NonNull<u8>,
    len: ffi::c_int,
}

impl Buffer {
    pub fn alloc(len: ffi::c_int) -> io::Result<Self> {
        NonNull::new(unsafe { sys::av_malloc(len as usize).cast::<u8>() })
            .map(|ptr| Buffer { ptr, len })
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr().cast_const(), self.len as usize) }
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len as usize) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe { sys::av_free(self.ptr.as_ptr().cast::<ffi::c_void>()) }
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, fmt)
    }
}
