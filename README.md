# exr-imageio-poc
PoC for an integer overflow vulnerability in ImageIO patched in iOS/macOS 26.5

## The vulnerability

There was an integer overflow in function `EXRReadPlugin::decodeBlockAppleEXR` prior to iOS/macOS 26.5 when calculating the size of a buffer.

It is possible to cause memory corruption by having the multiplication of the supplied image's `width` and `height` values wrap-around to `0`, and subsequently call `malloc_type_malloc` with a very small size.

Supplying an image file containing excess pixel data results in a heap overflow and a crash:
```
  thread #5, queue = 'com.apple.root.user-interactive-qos', stop reason = EXC_GUARD (code=1, subcode=0x4141414141414151)
    frame #0: 0x00000001855ba8c8 libdispatch.dylib`_dispatch_root_queue_drain + 176
libdispatch.dylib`_dispatch_root_queue_drain:
->  0x1855ba8c8 <+176>: ldr    x8, [x0, #0x10]!
    0x1855ba8cc <+180>: cbz    x8, 0x1855bab2c ; <+788>
    0x1855ba8d0 <+184>: str    x8, [x20, #0x68]
    0x1855ba8d4 <+188>: mov    x0, x20
Target 0: (exr_parser) stopped.
```

Full technical write-up available [here](https://zygosec.com/blog)
