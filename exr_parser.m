// credit: https://r00tkitsmm.github.io/fuzzing/2024/03/29/iOSImageIO.html
#include <Foundation/Foundation.h>
#include <Foundation/NSURL.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/shm.h>
#include <dirent.h>

#import <ImageIO/ImageIO.h>
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>

extern bool CGRenderingStateGetAllowsAcceleration(void*);
extern bool CGRenderingStateSetAllowsAcceleration(void*, bool);
extern void* CGContextGetRenderingState(CGContextRef);

void parse(char *filename) {

  printf("doing parse for %s\n", filename);

    // Read the file into memory
    NSData *data = [NSData dataWithContentsOfFile: [NSString stringWithFormat:@"%s", filename]];

    CFStringRef key = CFSTR("kCGImageSourceDecodeRequest");
    CFStringRef value = CFSTR("kCGImageSourceDecodeToSDR");

    CFDictionaryRef options = CFDictionaryCreate(
        kCFAllocatorDefault,
        (const void **)&key,
        (const void **)&value,
        1,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    // Create an image source from the data
    CGImageSourceRef source = CGImageSourceCreateWithData(
        (__bridge CFDataRef)data, 
        (__bridge CFDictionaryRef)options
    );

    // Decode into a CGImage
    CGImageRef cgImg = CGImageSourceCreateImageAtIndex(source, 0, options);
    // CGImageRef cgImg = [img CGImageForProposedRect:nil context:nil hints:nil];
    if (cgImg) {
        size_t width = CGImageGetWidth(cgImg);
        size_t height = CGImageGetHeight(cgImg);

        printf("width %x\n", width);
        printf("height %x\n", height);

        CGColorSpaceRef colorspace = CGColorSpaceCreateDeviceRGB();
        CGContextRef ctx = CGBitmapContextCreate(0, width, height, 8, 0, colorspace, 1);
        void* renderingState = CGContextGetRenderingState(ctx);
        CGRenderingStateSetAllowsAcceleration(renderingState, false);
        CGRect rect = CGRectMake(0, 0, width, height);
        CGContextDrawImage(ctx, rect, cgImg);


        printf("done draw image\n");

        CGColorSpaceRelease(colorspace);
        CGContextRelease(ctx);
        CGImageRelease(cgImg);
    } else {
        printf("cgImg failed\n");
    }
    
}
int main(int argc, const char* argv[]) {
   
    if(argc < 2) {
        printf("need an image file");
        return 0;
    }

    printf("exr parser\n");

    parse(argv[1]);

    return 0;
}
