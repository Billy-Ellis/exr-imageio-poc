# exr-imageio-poc
PoC for an integer overflow vulnerability in ImageIO patched in iOS/macOS 26.5

## The vulnerability

There was an integer overflow in function `EXRReadPlugin::decodeBlockAppleEXR` prior to iOS/macOS 26.5 when calculating the size of a buffer.

It is possible to cause memory corruption by having the multiplication of the supplied image's `width` and `height` values wrap-around to `0`, and subsequently call `malloc_type_malloc` with a very small size.

Full technical write-up available [here](https://zygosec.com/blog)
