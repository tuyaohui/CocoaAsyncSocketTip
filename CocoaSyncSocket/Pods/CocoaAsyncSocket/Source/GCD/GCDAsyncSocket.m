//
//  GCDAsyncSocket.m
//  
//  This class is in the public domain.
//  Originally created by Robbie Hanson in Q4 2010.
//  Updated and maintained by Deusty LLC and the Apple development community.
//
//  https://github.com/robbiehanson/CocoaAsyncSocket
//

#import "GCDAsyncSocket.h"

#if TARGET_OS_IPHONE
#import <CFNetwork/CFNetwork.h>
#endif

#import <TargetConditionals.h>
#import <arpa/inet.h>
#import <fcntl.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <netinet/in.h>
#import <net/if.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <sys/ioctl.h>
#import <sys/poll.h>
#import <sys/uio.h>
#import <sys/un.h>
#import <unistd.h>

#if ! __has_feature(objc_arc)
#warning This file must be compiled with ARC. Use -fobjc-arc flag (or convert project to ARC).
// For more information see: https://github.com/robbiehanson/CocoaAsyncSocket/wiki/ARC
#endif


#ifndef GCDAsyncSocketLoggingEnabled
#define GCDAsyncSocketLoggingEnabled 0
#endif

#if GCDAsyncSocketLoggingEnabled

// Logging Enabled - See log level below

// Logging uses the CocoaLumberjack framework (which is also GCD based).
// https://github.com/robbiehanson/CocoaLumberjack
// 
// It allows us to do a lot of logging without significantly slowing down the code.
#import "DDLog.h"

#define LogAsync   YES
#define LogContext GCDAsyncSocketLoggingContext

#define LogObjc(flg, frmt, ...) LOG_OBJC_MAYBE(LogAsync, logLevel, flg, LogContext, frmt, ##__VA_ARGS__)
#define LogC(flg, frmt, ...)    LOG_C_MAYBE(LogAsync, logLevel, flg, LogContext, frmt, ##__VA_ARGS__)

#define LogError(frmt, ...)     LogObjc(LOG_FLAG_ERROR,   (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogWarn(frmt, ...)      LogObjc(LOG_FLAG_WARN,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogInfo(frmt, ...)      LogObjc(LOG_FLAG_INFO,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogVerbose(frmt, ...)   LogObjc(LOG_FLAG_VERBOSE, (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)

#define LogCError(frmt, ...)    LogC(LOG_FLAG_ERROR,   (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCWarn(frmt, ...)     LogC(LOG_FLAG_WARN,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCInfo(frmt, ...)     LogC(LOG_FLAG_INFO,    (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)
#define LogCVerbose(frmt, ...)  LogC(LOG_FLAG_VERBOSE, (@"%@: " frmt), THIS_FILE, ##__VA_ARGS__)

#define LogTrace()              LogObjc(LOG_FLAG_VERBOSE, @"%@: %@", THIS_FILE, THIS_METHOD)
#define LogCTrace()             LogC(LOG_FLAG_VERBOSE, @"%@: %s", THIS_FILE, __FUNCTION__)

#ifndef GCDAsyncSocketLogLevel
#define GCDAsyncSocketLogLevel LOG_LEVEL_VERBOSE
#endif

// Log levels : off, error, warn, info, verbose
static const int logLevel = GCDAsyncSocketLogLevel;

#else

// Logging Disabled

#define LogError(frmt, ...)     {}
#define LogWarn(frmt, ...)      {}
#define LogInfo(frmt, ...)      {}
#define LogVerbose(frmt, ...)   {}

#define LogCError(frmt, ...)    {}
#define LogCWarn(frmt, ...)     {}
#define LogCInfo(frmt, ...)     {}
#define LogCVerbose(frmt, ...)  {}

#define LogTrace()              {}
#define LogCTrace(frmt, ...)    {}

#endif

/**
 * Seeing a return statements within an inner block
 * can sometimes be mistaken for a return point of the enclosing method.
 * This makes inline blocks a bit easier to read.
**/
#define return_from_block  return

/**
 * A socket file descriptor is really just an integer.
 * It represents the index of the socket within the kernel.
 * This makes invalid file descriptor comparisons easier to read.
**/
#define SOCKET_NULL -1


NSString *const GCDAsyncSocketException = @"GCDAsyncSocketException";
NSString *const GCDAsyncSocketErrorDomain = @"GCDAsyncSocketErrorDomain";

NSString *const GCDAsyncSocketQueueName = @"GCDAsyncSocket";
NSString *const GCDAsyncSocketThreadName = @"GCDAsyncSocket-CFStream";

NSString *const GCDAsyncSocketManuallyEvaluateTrust = @"GCDAsyncSocketManuallyEvaluateTrust";
#if TARGET_OS_IPHONE
NSString *const GCDAsyncSocketUseCFStreamForTLS = @"GCDAsyncSocketUseCFStreamForTLS";
#endif
NSString *const GCDAsyncSocketSSLPeerID = @"GCDAsyncSocketSSLPeerID";
NSString *const GCDAsyncSocketSSLProtocolVersionMin = @"GCDAsyncSocketSSLProtocolVersionMin";
NSString *const GCDAsyncSocketSSLProtocolVersionMax = @"GCDAsyncSocketSSLProtocolVersionMax";
NSString *const GCDAsyncSocketSSLSessionOptionFalseStart = @"GCDAsyncSocketSSLSessionOptionFalseStart";
NSString *const GCDAsyncSocketSSLSessionOptionSendOneByteRecord = @"GCDAsyncSocketSSLSessionOptionSendOneByteRecord";
NSString *const GCDAsyncSocketSSLCipherSuites = @"GCDAsyncSocketSSLCipherSuites";
#if !TARGET_OS_IPHONE
NSString *const GCDAsyncSocketSSLDiffieHellmanParameters = @"GCDAsyncSocketSSLDiffieHellmanParameters";
#endif

enum GCDAsyncSocketFlags
{
	kSocketStarted                 = 1 <<  0,  // If set, socket has been started (accepting/connecting)
	kConnected                     = 1 <<  1,  // If set, the socket is connected
	kForbidReadsWrites             = 1 <<  2,  // If set, no new reads or writes are allowed
	kReadsPaused                   = 1 <<  3,  // If set, reads are paused due to possible timeout
	kWritesPaused                  = 1 <<  4,  // If set, writes are paused due to possible timeout
	kDisconnectAfterReads          = 1 <<  5,  // If set, disconnect after no more reads are queued
	kDisconnectAfterWrites         = 1 <<  6,  // If set, disconnect after no more writes are queued
	kSocketCanAcceptBytes          = 1 <<  7,  // If set, we know socket can accept bytes. If unset, it's unknown.
	kReadSourceSuspended           = 1 <<  8,  // If set, the read source is suspended
	kWriteSourceSuspended          = 1 <<  9,  // If set, the write source is suspended
	kQueuedTLS                     = 1 << 10,  // If set, we've queued an upgrade to TLS
	kStartingReadTLS               = 1 << 11,  // If set, we're waiting for TLS negotiation to complete
	kStartingWriteTLS              = 1 << 12,  // If set, we're waiting for TLS negotiation to complete
	kSocketSecure                  = 1 << 13,  // If set, socket is using secure communication via SSL/TLS
	kSocketHasReadEOF              = 1 << 14,  // If set, we have read EOF from socket
	kReadStreamClosed              = 1 << 15,  // If set, we've read EOF plus prebuffer has been drained
	kDealloc                       = 1 << 16,  // If set, the socket is being deallocated
#if TARGET_OS_IPHONE
	kAddedStreamsToRunLoop         = 1 << 17,  // If set, CFStreams have been added to listener thread
	kUsingCFStreamForTLS           = 1 << 18,  // If set, we're forced to use CFStream instead of SecureTransport
	kSecureSocketHasBytesAvailable = 1 << 19,  // If set, CFReadStream has notified us of bytes available
#endif
};

enum GCDAsyncSocketConfig
{
	kIPv4Disabled              = 1 << 0,  // If set, IPv4 is disabled
	kIPv6Disabled              = 1 << 1,  // If set, IPv6 is disabled
	kPreferIPv6                = 1 << 2,  // If set, IPv6 is preferred over IPv4
	kAllowHalfDuplexConnection = 1 << 3,  // If set, the socket will stay open even if the read stream closes
};

#if TARGET_OS_IPHONE
  static NSThread *cfstreamThread;  // Used for CFStreams


  static uint64_t cfstreamThreadRetainCount;   // setup & teardown
  static dispatch_queue_t cfstreamThreadSetupQueue; // setup & teardown
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * A PreBuffer is used when there is more data available on the socket
 * than is being requested by current read request.
 * In this case we slurp up all data from the socket (to minimize sys calls),
 * and store additional yet unread data in a "prebuffer".
 * 
 * The prebuffer is entirely drained before we read from the socket again.
 * In other words, a large chunk of data is written is written to the prebuffer.
 * The prebuffer is then drained via a series of one or more reads (for subsequent read request(s)).
 * 
 * A ring buffer was once used for this purpose.
 * But a ring buffer takes up twice as much memory as needed (double the size for mirroring).
 * In fact, it generally takes up more than twice the needed size as everything has to be rounded up to vm_page_size.
 * And since the prebuffer is always completely drained after being written to, a full ring buffer isn't needed.
 * 
 * The current design is very simple and straight-forward, while also keeping memory requirements lower.
**/

@interface GCDAsyncSocketPreBuffer : NSObject
{
    //unsigned char
    //提前的指针，指向这块提前的缓冲区
	uint8_t *preBuffer;
    //size_t 它是一个与机器相关的unsigned类型，其大小足以保证存储内存中对象的大小。
    //它可以存储在理论上是可能的任何类型的数组的最大大小
	size_t preBufferSize;
	//读的指针
	uint8_t *readPointer;
    //写的指针
	uint8_t *writePointer;
}

- (id)initWithCapacity:(size_t)numBytes;

- (void)ensureCapacityForWrite:(size_t)numBytes;

- (size_t)availableBytes;
- (uint8_t *)readBuffer;

- (void)getReadBuffer:(uint8_t **)bufferPtr availableBytes:(size_t *)availableBytesPtr;

- (size_t)availableSpace;
- (uint8_t *)writeBuffer;

- (void)getWriteBuffer:(uint8_t **)bufferPtr availableSpace:(size_t *)availableSpacePtr;

- (void)didRead:(size_t)bytesRead;
- (void)didWrite:(size_t)bytesWritten;

- (void)reset;

@end

@implementation GCDAsyncSocketPreBuffer

//初始化
- (id)initWithCapacity:(size_t)numBytes
{
	if ((self = [super init]))
	{
        //设置size
		preBufferSize = numBytes;
        //申请size大小的内存给preBuffer
		preBuffer = malloc(preBufferSize);
		
        //为同一个值
		readPointer = preBuffer;
		writePointer = preBuffer;
	}
	return self;
}

- (void)dealloc
{
	if (preBuffer)
		free(preBuffer);
}

//确认读的大小
- (void)ensureCapacityForWrite:(size_t)numBytes
{
    //拿到当前可用的空间大小
	size_t availableSpace = [self availableSpace];
	
    //如果申请的大小大于可用的大小
	if (numBytes > availableSpace)
	{
        //需要多出来的大小
		size_t additionalBytes = numBytes - availableSpace;
		//新的总大小
		size_t newPreBufferSize = preBufferSize + additionalBytes;
        //重新去分配preBuffer
		uint8_t *newPreBuffer = realloc(preBuffer, newPreBufferSize);
		
        //读的指针偏移量（已读大小）
		size_t readPointerOffset = readPointer - preBuffer;
        //写的指针偏移量（已写大小）
		size_t writePointerOffset = writePointer - preBuffer;
        //提前的Buffer重新复制
		preBuffer = newPreBuffer;
        //大小重新赋值
		preBufferSize = newPreBufferSize;
		
        //读写指针重新赋值 + 上偏移量
		readPointer = preBuffer + readPointerOffset;
		writePointer = preBuffer + writePointerOffset;
	}
}
//仍然可读的数据，过程是先写后读，只有写的大于读的，才能让你继续去读，不然没数据可读了
- (size_t)availableBytes
{
	return writePointer - readPointer;
}

- (uint8_t *)readBuffer
{
	return readPointer;
}

- (void)getReadBuffer:(uint8_t **)bufferPtr availableBytes:(size_t *)availableBytesPtr
{
	if (bufferPtr) *bufferPtr = readPointer;
	if (availableBytesPtr) *availableBytesPtr = [self availableBytes];
}

//读数据的指针
- (void)didRead:(size_t)bytesRead
{
	readPointer += bytesRead;
	//如果读了这么多，指针和写的指针还相同的话，说明已经读完，重置指针到最初的位置
	if (readPointer == writePointer)
	{
		// The prebuffer has been drained. Reset pointers.
		readPointer  = preBuffer;
		writePointer = preBuffer;
	}
}
//prebuffer的剩余空间  = preBufferSize（总大小） - （写的头指针 - preBuffer一开的指针，即已被写的大小）

- (size_t)availableSpace
{
	return preBufferSize - (writePointer - preBuffer);
}

- (uint8_t *)writeBuffer
{
	return writePointer;
}

- (void)getWriteBuffer:(uint8_t **)bufferPtr availableSpace:(size_t *)availableSpacePtr
{
	if (bufferPtr) *bufferPtr = writePointer;
	if (availableSpacePtr) *availableSpacePtr = [self availableSpace];
}

- (void)didWrite:(size_t)bytesWritten
{
	writePointer += bytesWritten;
}

- (void)reset
{
	readPointer  = preBuffer;
	writePointer = preBuffer;
}

@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * The GCDAsyncReadPacket encompasses the instructions for any given read.
 * The content of a read packet allows the code to determine if we're:
 *  - reading to a certain length
 *  - reading to a certain separator
 *  - or simply reading the first chunk of available data
**/
@interface GCDAsyncReadPacket : NSObject
{
  @public
    //当前包的数据 ，（容器，有可能为空）
	NSMutableData *buffer;
    //开始偏移 （数据在容器中开始写的偏移）
	NSUInteger startOffset;
    //已读字节数 （已经写了个字节数）
	NSUInteger bytesDone;
    
    //想要读取数据的最大长度 （有可能没有）
	NSUInteger maxLength;
    //超时时长
	NSTimeInterval timeout;
    //当前需要读取总长度  （这一次read读取的长度，不一定有，如果没有则可用maxLength）
	NSUInteger readLength;
    
    //包的边界标识数据 （可能没有）
	NSData *term;
    //判断buffer的拥有者是不是这个类，还是用户。
    //跟初始化传不传一个buffer进来有关，如果传了，则拥有者为用户 NO， 否则为YES
	BOOL bufferOwner;
    //原始传过来的data长度
	NSUInteger originalBufferLength;
    //数据包的tag
	long tag;
}
//初始化
- (id)initWithData:(NSMutableData *)d
       startOffset:(NSUInteger)s
         maxLength:(NSUInteger)m
           timeout:(NSTimeInterval)t
        readLength:(NSUInteger)l
        terminator:(NSData *)e
               tag:(long)i;

//确保容器大小给多余的长度
- (void)ensureCapacityForAdditionalDataOfLength:(NSUInteger)bytesToRead;
////预期中读的大小，决定是否走preBuffer
- (NSUInteger)optimalReadLengthWithDefault:(NSUInteger)defaultValue shouldPreBuffer:(BOOL *)shouldPreBufferPtr;
//读取指定长度的数据
- (NSUInteger)readLengthForNonTermWithHint:(NSUInteger)bytesAvailable;

//上两个方法的综合
- (NSUInteger)readLengthForTermWithHint:(NSUInteger)bytesAvailable shouldPreBuffer:(BOOL *)shouldPreBufferPtr;

//根据一个终结符去读数据，直到读到终结的位置或者最大数据的位置，返回值为该包的确定长度
- (NSUInteger)readLengthForTermWithPreBuffer:(GCDAsyncSocketPreBuffer *)preBuffer found:(BOOL *)foundPtr;
////查找终结符，在prebuffer之后，返回值为该包的确定长度
- (NSInteger)searchForTermAfterPreBuffering:(ssize_t)numBytes;

@end

@implementation GCDAsyncReadPacket

//初始化方法
- (id)initWithData:(NSMutableData *)d
       startOffset:(NSUInteger)s
         maxLength:(NSUInteger)m
           timeout:(NSTimeInterval)t
        readLength:(NSUInteger)l
        terminator:(NSData *)e
               tag:(long)i
{
	if((self = [super init]))
	{
        //已读大小
		bytesDone = 0;
		maxLength = m;
		timeout = t;
		readLength = l;
		term = [e copy];
		tag = i;
		
        //有数据直接赋值
		if (d)
		{
			buffer = d;
			startOffset = s;
			bufferOwner = NO;
			originalBufferLength = [d length];
		}
		else
		{
            //生成对应读取长度的Buffer，空的
			if (readLength > 0)
				buffer = [[NSMutableData alloc] initWithLength:readLength];
			else
				buffer = [[NSMutableData alloc] initWithLength:0];
			//开始偏移设置为0
			startOffset = 0;
            //
			bufferOwner = YES;
            //原始数据长度设置为0
			originalBufferLength = 0;
		}
	}
	return self;
}

/**
 * Increases the length of the buffer (if needed) to ensure a read of the given size will fit.
**/
- (void)ensureCapacityForAdditionalDataOfLength:(NSUInteger)bytesToRead
{
    //数据长度
	NSUInteger buffSize = [buffer length];
    
    //获取到packet使用的长度
	NSUInteger buffUsed = startOffset + bytesDone;
	
    //得到空的长度
	NSUInteger buffSpace = buffSize - buffUsed;
	
    //如果需要读的长度大于空的长度
	if (bytesToRead > buffSpace)
	{
		NSUInteger buffInc = bytesToRead - buffSpace;
		//增长多需要的长度，data的方法
		[buffer increaseLengthBy:buffInc];
	}
}

/**
 * This method is used when we do NOT know how much data is available to be read from the socket.
 * This method returns the default value unless it exceeds the specified readLength or maxLength.
 * 
 * Furthermore, the shouldPreBuffer decision is based upon the packet type,
 * and whether the returned value would fit in the current buffer without requiring a resize of the buffer.
**/

//理想中读的大小，是否走preBuffer
- (NSUInteger)optimalReadLengthWithDefault:(NSUInteger)defaultValue shouldPreBuffer:(BOOL *)shouldPreBufferPtr
{
	NSUInteger result;
	
    //如果readlength大于0，说明它起作用
	if (readLength > 0)
	{
		// Read a specific length of data
		//得到小的
		result = MIN(defaultValue, (readLength - bytesDone));
		
		// There is no need to prebuffer since we know exactly how much data we need to read.
		// Even if the buffer isn't currently big enough to fit this amount of data,
		// it would have to be resized eventually anyway.
		//如果确切知道要多大的数据，就不走prebuffer?
		if (shouldPreBufferPtr)
			*shouldPreBufferPtr = NO;
	}
	else
	{
		// Either reading until we find a specified terminator,
		// or we're simply reading all available data.
		// 
		// In other words, one of:
		// 
		// - readDataToData packet
		// - readDataWithTimeout packet
		
        //还是要小的
		if (maxLength > 0)
			result =  MIN(defaultValue, (maxLength - bytesDone));
		else
			result = defaultValue;
		
		// Since we don't know the size of the read in advance,
		// the shouldPreBuffer decision is based upon whether the returned value would fit
		// in the current buffer without requiring a resize of the buffer.
		// 
		// This is because, in all likelyhood, the amount read from the socket will be less than the default value.
		// Thus we should avoid over-allocating the read buffer when we can simply use the pre-buffer instead.
		//我们不知道要读多大，所以用不用prebuffer取决于，返回的值大小是否正合适
		if (shouldPreBufferPtr)
		{
            //拿到当前读包数据大小
			NSUInteger buffSize = [buffer length];
            //得到已经写完的大小
			NSUInteger buffUsed = startOffset + bytesDone;
			//还剩下的空间
			NSUInteger buffSpace = buffSize - buffUsed;
            //如果还剩下的空间大小大于等于这次去读取数据的大小，则不用prebuffer，直接读。小的话，则用prebuffer来缓冲，在把数据从prebuffer中读出
			if (buffSpace >= result)
				*shouldPreBufferPtr = NO;
			else
				*shouldPreBufferPtr = YES;
		}
	}
	
	return result;
}

/**
 * For read packets without a set terminator, returns the amount of data
 * that can be read without exceeding the readLength or maxLength.
 * 
 * The given parameter indicates the number of bytes estimated to be available on the socket,
 * which is taken into consideration during the calculation.
 * 
 * The given hint MUST be greater than zero.
**/
//读取指定长度的数据
- (NSUInteger)readLengthForNonTermWithHint:(NSUInteger)bytesAvailable
{
    //断言界限标记为空
	NSAssert(term == nil, @"This method does not apply to term reads");
    //断言传入的参数大于0
	NSAssert(bytesAvailable > 0, @"Invalid parameter: bytesAvailable");
	
    //直接返回要读长度和数据包剩余未读长度中 小的那个值
	if (readLength > 0)
	{
		// Read a specific length of data
		//
		return MIN(bytesAvailable, (readLength - bytesDone));
		
		// No need to avoid resizing the buffer.
		// If the user provided their own buffer,
		// and told us to read a certain length of data that exceeds the size of the buffer,
		// then it is clear that our code will resize the buffer during the read operation.
		// 
		// This method does not actually do any resizing.
		// The resizing will happen elsewhere if needed.
	}
	else
	{
		// Read all available data
		
		NSUInteger result = bytesAvailable;
		
		if (maxLength > 0)
		{
			result = MIN(result, (maxLength - bytesDone));
		}
		
		// No need to avoid resizing the buffer.
		// If the user provided their own buffer,
		// and told us to read all available data without giving us a maxLength,
		// then it is clear that our code might resize the buffer during the read operation.
		// 
		// This method does not actually do any resizing.
		// The resizing will happen elsewhere if needed.
		
		return result;
	}
}

/**
 * For read packets with a set terminator, returns the amount of data
 * that can be read without exceeding the maxLength.
 * 
 * The given parameter indicates the number of bytes estimated to be available on the socket,
 * which is taken into consideration during the calculation.
 * 
 * To optimize memory allocations, mem copies, and mem moves
 * the shouldPreBuffer boolean value will indicate if the data should be read into a prebuffer first,
 * or if the data can be read directly into the read packet's buffer.
**/
//给个边界标记，返回应该读取的数据数量

- (NSUInteger)readLengthForTermWithHint:(NSUInteger)bytesAvailable shouldPreBuffer:(BOOL *)shouldPreBufferPtr
{
	NSAssert(term != nil, @"This method does not apply to non-term reads");
	NSAssert(bytesAvailable > 0, @"Invalid parameter: bytesAvailable");
	
	
	NSUInteger result = bytesAvailable;
	
	if (maxLength > 0)
	{
		result = MIN(result, (maxLength - bytesDone));
	}
	
	// Should the data be read into the read packet's buffer, or into a pre-buffer first?
	// 
	// One would imagine the preferred option is the faster one.
	// So which one is faster?
	// 
	// Reading directly into the packet's buffer requires:
	// 1. Possibly resizing packet buffer (malloc/realloc)
	// 2. Filling buffer (read)
	// 3. Searching for term (memcmp)
	// 4. Possibly copying overflow into prebuffer (malloc/realloc, memcpy)
	// 
	// Reading into prebuffer first:
	// 1. Possibly resizing prebuffer (malloc/realloc)
	// 2. Filling buffer (read)
	// 3. Searching for term (memcmp)
	// 4. Copying underflow into packet buffer (malloc/realloc, memcpy)
	// 5. Removing underflow from prebuffer (memmove)
	// 
	// Comparing the performance of the two we can see that reading
	// data into the prebuffer first is slower due to the extra memove.
	// 
	// However:
	// The implementation of NSMutableData is open source via core foundation's CFMutableData.
	// Decreasing the length of a mutable data object doesn't cause a realloc.
	// In other words, the capacity of a mutable data object can grow, but doesn't shrink.
	// 
	// This means the prebuffer will rarely need a realloc.
	// The packet buffer, on the other hand, may often need a realloc.
	// This is especially true if we are the buffer owner.
	// Furthermore, if we are constantly realloc'ing the packet buffer,
	// and then moving the overflow into the prebuffer,
	// then we're consistently over-allocating memory for each term read.
	// And now we get into a bit of a tradeoff between speed and memory utilization.
	// 
	// The end result is that the two perform very similarly.
	// And we can answer the original question very simply by another means.
	// 
	// If we can read all the data directly into the packet's buffer without resizing it first,
	// then we do so. Otherwise we use the prebuffer.
	
	if (shouldPreBufferPtr)
	{
		NSUInteger buffSize = [buffer length];
		NSUInteger buffUsed = startOffset + bytesDone;
		
		if ((buffSize - buffUsed) >= result)
			*shouldPreBufferPtr = NO;
		else
			*shouldPreBufferPtr = YES;
	}
	
	return result;
}

/**
 * For read packets with a set terminator,
 * returns the amount of data that can be read from the given preBuffer,
 * without going over a terminator or the maxLength.
 * 
 * It is assumed the terminator has not already been read.
**/
//根据一个终结去读数据，直到读到终结的位置或者最大数据的位置，返回值为该包的确定长度
- (NSUInteger)readLengthForTermWithPreBuffer:(GCDAsyncSocketPreBuffer *)preBuffer found:(BOOL *)foundPtr
{
    //断言终结标志不为空
	NSAssert(term != nil, @"This method does not apply to non-term reads");
    //断言有可读的数据
	NSAssert([preBuffer availableBytes] > 0, @"Invoked with empty pre buffer!");
	
	// We know that the terminator, as a whole, doesn't exist in our own buffer.
	// But it is possible that a _portion_ of it exists in our buffer.
	// So we're going to look for the terminator starting with a portion of our own buffer.
	// 
	// Example:
	// 
	// term length      = 3 bytes
	// bytesDone        = 5 bytes
	// preBuffer length = 5 bytes
	// 
	// If we append the preBuffer to our buffer,
	// it would look like this:
	// 
	// ---------------------
	// |B|B|B|B|B|P|P|P|P|P|
	// ---------------------
	// 
	// So we start our search here:
	// 
	// ---------------------
	// |B|B|B|B|B|P|P|P|P|P|
	// -------^-^-^---------
	// 
	// And move forwards...
	// 
	// ---------------------
	// |B|B|B|B|B|P|P|P|P|P|
	// ---------^-^-^-------
	// 
	// Until we find the terminator or reach the end.
	// 
	// ---------------------
	// |B|B|B|B|B|P|P|P|P|P|
	// ---------------^-^-^-
	
	BOOL found = NO;
	
	NSUInteger termLength = [term length];
	NSUInteger preBufferLength = [preBuffer availableBytes];
	
	if ((bytesDone + preBufferLength) < termLength)
	{
		// Not enough data for a full term sequence yet
		return preBufferLength;
	}
	
	NSUInteger maxPreBufferLength;
	if (maxLength > 0) {
		maxPreBufferLength = MIN(preBufferLength, (maxLength - bytesDone));
		
		// Note: maxLength >= termLength
	}
	else {
		maxPreBufferLength = preBufferLength;
	}
	
	uint8_t seq[termLength];
	const void *termBuf = [term bytes];
	
	NSUInteger bufLen = MIN(bytesDone, (termLength - 1));
	uint8_t *buf = (uint8_t *)[buffer mutableBytes] + startOffset + bytesDone - bufLen;
	
	NSUInteger preLen = termLength - bufLen;
	const uint8_t *pre = [preBuffer readBuffer];
	
	NSUInteger loopCount = bufLen + maxPreBufferLength - termLength + 1; // Plus one. See example above.
	
	NSUInteger result = maxPreBufferLength;
	
	NSUInteger i;
	for (i = 0; i < loopCount; i++)
	{
		if (bufLen > 0)
		{
			// Combining bytes from buffer and preBuffer
			
			memcpy(seq, buf, bufLen);
			memcpy(seq + bufLen, pre, preLen);
			
			if (memcmp(seq, termBuf, termLength) == 0)
			{
				result = preLen;
				found = YES;
				break;
			}
			
			buf++;
			bufLen--;
			preLen++;
		}
		else
		{
			// Comparing directly from preBuffer
			
			if (memcmp(pre, termBuf, termLength) == 0)
			{
				NSUInteger preOffset = pre - [preBuffer readBuffer]; // pointer arithmetic
				
				result = preOffset + termLength;
				found = YES;
				break;
			}
			
			pre++;
		}
	}
	
	// There is no need to avoid resizing the buffer in this particular situation.
	
	if (foundPtr) *foundPtr = found;
	return result;
}

/**
 * For read packets with a set terminator, scans the packet buffer for the term.
 * It is assumed the terminator had not been fully read prior to the new bytes.
 * 
 * If the term is found, the number of excess bytes after the term are returned.
 * If the term is not found, this method will return -1.
 * 
 * Note: A return value of zero means the term was found at the very end.
 * 
 * Prerequisites:
 * The given number of bytes have been added to the end of our buffer.
 * Our bytesDone variable has NOT been changed due to the prebuffered bytes.
**/

//查找终结符，在prebuffer之后，返回值为该包的确定长度
- (NSInteger)searchForTermAfterPreBuffering:(ssize_t)numBytes
{
    //断言有边界标识
	NSAssert(term != nil, @"This method does not apply to non-term reads");
	
	// The implementation of this method is very similar to the above method.
	// See the above method for a discussion of the algorithm used here.
	
    //拿到包的指针
	uint8_t *buff = [buffer mutableBytes];
    
    //总共写的字节数
	NSUInteger buffLength = bytesDone + numBytes;
	
    //拿到边界的指针位置
	const void *termBuff = [term bytes];
    //拿到term的长度
	NSUInteger termLength = [term length];
	
	// Note: We are dealing with unsigned integers,
	// so make sure the math doesn't go below zero.
	
	NSUInteger i = ((buffLength - numBytes) >= termLength) ? (buffLength - numBytes - termLength + 1) : 0;
	
	while (i + termLength <= buffLength)
	{
		uint8_t *subBuffer = buff + startOffset + i;
		
		if (memcmp(subBuffer, termBuff, termLength) == 0)
		{
			return buffLength - (i + termLength);
		}
		
		i++;
	}
	
	return -1;
}


@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * The GCDAsyncWritePacket encompasses the instructions for any given write.
**/
@interface GCDAsyncWritePacket : NSObject
{
  @public
    //需要写的数据
	NSData *buffer;
    //已写大小
	NSUInteger bytesDone;
	long tag;
	NSTimeInterval timeout;
}
- (id)initWithData:(NSData *)d timeout:(NSTimeInterval)t tag:(long)i;
@end

@implementation GCDAsyncWritePacket

- (id)initWithData:(NSData *)d timeout:(NSTimeInterval)t tag:(long)i
{
	if((self = [super init]))
	{
		buffer = d; // Retain not copy. For performance as documented in header file.
		bytesDone = 0;
		timeout = t;
		tag = i;
	}
	return self;
}


@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * The GCDAsyncSpecialPacket encompasses special instructions for interruptions in the read/write queues.
 * This class my be altered to support more than just TLS in the future.
**/
@interface GCDAsyncSpecialPacket : NSObject
{
  @public
	NSDictionary *tlsSettings;
}
- (id)initWithTLSSettings:(NSDictionary *)settings;
@end

@implementation GCDAsyncSpecialPacket

- (id)initWithTLSSettings:(NSDictionary *)settings
{
	if((self = [super init]))
	{
		tlsSettings = [settings copy];
	}
	return self;
}


@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

@implementation GCDAsyncSocket
{
    //flags，当前正在做操作的标识符
	uint32_t flags;
	uint16_t config;
	
    //代理
	__weak id<GCDAsyncSocketDelegate> delegate;
    //代理回调的queue
	dispatch_queue_t delegateQueue;
	
    //本地IPV4Socket
	int socket4FD;
    //本地IPV6Socket
	int socket6FD;
    //unix域的套接字
	int socketUN;
    //unix域 服务端 url
	NSURL *socketUrl;
    //状态Index
	int stateIndex;
    
    //本机的IPV4地址
	NSData * connectInterface4;
    //本机的IPV6地址
	NSData * connectInterface6;
    //本机unix域地址
	NSData * connectInterfaceUN;
	
    //这个类的对Socket的操作都在这个queue中，串行
	dispatch_queue_t socketQueue;
	
	dispatch_source_t accept4Source;
	dispatch_source_t accept6Source;
	dispatch_source_t acceptUNSource;
    
    //连接timer,GCD定时器
	dispatch_source_t connectTimer;
	dispatch_source_t readSource;
	dispatch_source_t writeSource;
	dispatch_source_t readTimer;
	dispatch_source_t writeTimer;
   
    //读写数据包数组 类似queue，最大限制为5个包
	NSMutableArray *readQueue;
	NSMutableArray *writeQueue;
	
    //当前正在读写数据包
	GCDAsyncReadPacket *currentRead;
	GCDAsyncWritePacket *currentWrite;
	//当前socket未获取完的数据大小
	unsigned long socketFDBytesAvailable;
	
    //全局公用的提前缓冲区
	GCDAsyncSocketPreBuffer *preBuffer;
		
#if TARGET_OS_IPHONE
	CFStreamClientContext streamContext;
    //读的数据流
	CFReadStreamRef readStream;
    //写的数据流
	CFWriteStreamRef writeStream;
#endif
    //SSL上下文，用来做SSL认证
	SSLContextRef sslContext;
    
    //全局公用的SSL的提前缓冲区
	GCDAsyncSocketPreBuffer *sslPreBuffer;
	size_t sslWriteCachedLength;
    
    //记录SSL读取数据错误
	OSStatus sslErrCode;
    //记录SSL握手的错误
    OSStatus lastSSLHandshakeError;
	
    //socket队列的标识key
	void *IsOnSocketQueueOrTargetQueueKey;
	
	id userData;
    
    //连接备选服务端地址的延时 （另一个IPV4或IPV6）
    NSTimeInterval alternateAddressDelay;
}

#pragma mark - --------------------初始化---------------------------------
//层级调用
- (id)init
{
	return [self initWithDelegate:nil delegateQueue:NULL socketQueue:NULL];
}

- (id)initWithSocketQueue:(dispatch_queue_t)sq
{
	return [self initWithDelegate:nil delegateQueue:NULL socketQueue:sq];
}

- (id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq
{
	return [self initWithDelegate:aDelegate delegateQueue:dq socketQueue:NULL];
}

- (id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq socketQueue:(dispatch_queue_t)sq
{
	if((self = [super init]))
	{
		delegate = aDelegate;
		delegateQueue = dq;
		
         //这个宏是在sdk6.0之后才有的,如果是之前的,则OS_OBJECT_USE_OBJC为0，!0即执行if语句
        //对6.0的适配，如果是6.0以下，则去retain release，6.0之后ARC也管理了GCD
		#if !OS_OBJECT_USE_OBJC
        
		if (dq) dispatch_retain(dq);
		#endif
		
        //创建socket，先都置为 -1
        //本机的ipv4
		socket4FD = SOCKET_NULL;
        //ipv6
		socket6FD = SOCKET_NULL;
        //应该是UnixSocket
		socketUN = SOCKET_NULL;
        //url
		socketUrl = nil;
        //状态
		stateIndex = 0;
		
		if (sq)
		{
            //如果scoketQueue是global的,则报错。断言必须要一个非并行queue。
			NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0),
			         @"The given socketQueue parameter must not be a concurrent queue.");
			NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0),
			         @"The given socketQueue parameter must not be a concurrent queue.");
			NSAssert(sq != dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
			         @"The given socketQueue parameter must not be a concurrent queue.");
			//拿到scoketQueue
			socketQueue = sq;
            //iOS6之下retain
			#if !OS_OBJECT_USE_OBJC
			dispatch_retain(sq);
			#endif
		}
		else
		{
            //没有的话创建一个，  名字为：GCDAsyncSocket,串行
			socketQueue = dispatch_queue_create([GCDAsyncSocketQueueName UTF8String], NULL);
		}
		
		// The dispatch_queue_set_specific() and dispatch_get_specific() functions take a "void *key" parameter.
		// From the documentation:
		//
		// > Keys are only compared as pointers and are never dereferenced.
		// > Thus, you can use a pointer to a static variable for a specific subsystem or
		// > any other value that allows you to identify the value uniquely.
		//
		// We're just going to use the memory address of an ivar.
		// Specifically an ivar that is explicitly named for our purpose to make the code more readable.
		//
		// However, it feels tedious (and less readable) to include the "&" all the time:
		// dispatch_get_specific(&IsOnSocketQueueOrTargetQueueKey)
		//
		// So we're going to make it so it doesn't matter if we use the '&' or not,
		// by assigning the value of the ivar to the address of the ivar.
		// Thus: IsOnSocketQueueOrTargetQueueKey == &IsOnSocketQueueOrTargetQueueKey;
		
        
        //比如原来为   0X123 -> NULL 变成  0X222->0X123->NULL
        //自己的指针等于自己原来的指针，成二级指针了  看了注释是为了以后省略&,让代码更可读？
		IsOnSocketQueueOrTargetQueueKey = &IsOnSocketQueueOrTargetQueueKey;
		
        
		void *nonNullUnusedPointer = (__bridge void *)self;
        
        //dispatch_queue_set_specific给当前队里加一个标识 dispatch_get_specific当前线程取出这个标识，判断是不是在这个队列
        //这个key的值其实就是一个一级指针的地址  ，第三个参数把自己传过去了，上下文对象？第4个参数，为销毁的时候用的，可以指定一个函数
		dispatch_queue_set_specific(socketQueue, IsOnSocketQueueOrTargetQueueKey, nonNullUnusedPointer, NULL);
		//读的数组 限制为5
		readQueue = [[NSMutableArray alloc] initWithCapacity:5];
		currentRead = nil;
		
        //写的数组，限制5
		writeQueue = [[NSMutableArray alloc] initWithCapacity:5];
		currentWrite = nil;
		
        //设置大小为 4kb
		preBuffer = [[GCDAsyncSocketPreBuffer alloc] initWithCapacity:(1024 * 4)];
    
#pragma mark alternateAddressDelay??
        //交替地址延时？？ wtf
        alternateAddressDelay = 0.3;
	}
	return self;
}

- (void)dealloc
{
	LogInfo(@"%@ - %@ (start)", THIS_METHOD, self);
	
	// Set dealloc flag.
	// This is used by closeWithError to ensure we don't accidentally retain ourself.
	flags |= kDealloc;
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		[self closeWithError:nil];
	}
	else
	{
		dispatch_sync(socketQueue, ^{
			[self closeWithError:nil];
		});
	}
	
	delegate = nil;
	
	#if !OS_OBJECT_USE_OBJC
	if (delegateQueue) dispatch_release(delegateQueue);
	#endif
	delegateQueue = NULL;
	
	#if !OS_OBJECT_USE_OBJC
	if (socketQueue) dispatch_release(socketQueue);
	#endif
	socketQueue = NULL;
	
	LogInfo(@"%@ - %@ (finish)", THIS_METHOD, self);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Configuration
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (id)delegate
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return delegate;
	}
	else
	{
		__block id result;
		
		dispatch_sync(socketQueue, ^{
			result = delegate;
		});
		
		return result;
	}
}

- (void)setDelegate:(id)newDelegate synchronously:(BOOL)synchronously
{
	dispatch_block_t block = ^{
		delegate = newDelegate;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
		block();
	}
	else {
		if (synchronously)
			dispatch_sync(socketQueue, block);
		else
			dispatch_async(socketQueue, block);
	}
}

- (void)setDelegate:(id)newDelegate
{
	[self setDelegate:newDelegate synchronously:NO];
}

- (void)synchronouslySetDelegate:(id)newDelegate
{
	[self setDelegate:newDelegate synchronously:YES];
}

- (dispatch_queue_t)delegateQueue
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return delegateQueue;
	}
	else
	{
		__block dispatch_queue_t result;
		
		dispatch_sync(socketQueue, ^{
			result = delegateQueue;
		});
		
		return result;
	}
}

- (void)setDelegateQueue:(dispatch_queue_t)newDelegateQueue synchronously:(BOOL)synchronously
{
	dispatch_block_t block = ^{
		
		#if !OS_OBJECT_USE_OBJC
		if (delegateQueue) dispatch_release(delegateQueue);
		if (newDelegateQueue) dispatch_retain(newDelegateQueue);
		#endif
		
		delegateQueue = newDelegateQueue;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
		block();
	}
	else {
		if (synchronously)
			dispatch_sync(socketQueue, block);
		else
			dispatch_async(socketQueue, block);
	}
}

- (void)setDelegateQueue:(dispatch_queue_t)newDelegateQueue
{
	[self setDelegateQueue:newDelegateQueue synchronously:NO];
}

- (void)synchronouslySetDelegateQueue:(dispatch_queue_t)newDelegateQueue
{
	[self setDelegateQueue:newDelegateQueue synchronously:YES];
}

- (void)getDelegate:(id<GCDAsyncSocketDelegate> *)delegatePtr delegateQueue:(dispatch_queue_t *)delegateQueuePtr
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (delegatePtr) *delegatePtr = delegate;
		if (delegateQueuePtr) *delegateQueuePtr = delegateQueue;
	}
	else
	{
		__block id dPtr = NULL;
		__block dispatch_queue_t dqPtr = NULL;
		
		dispatch_sync(socketQueue, ^{
			dPtr = delegate;
			dqPtr = delegateQueue;
		});
		
		if (delegatePtr) *delegatePtr = dPtr;
		if (delegateQueuePtr) *delegateQueuePtr = dqPtr;
	}
}

- (void)setDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue synchronously:(BOOL)synchronously
{
	dispatch_block_t block = ^{
		
		delegate = newDelegate;
		
		#if !OS_OBJECT_USE_OBJC
		if (delegateQueue) dispatch_release(delegateQueue);
		if (newDelegateQueue) dispatch_retain(newDelegateQueue);
		#endif
		
		delegateQueue = newDelegateQueue;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey)) {
		block();
	}
	else {
		if (synchronously)
			dispatch_sync(socketQueue, block);
		else
			dispatch_async(socketQueue, block);
	}
}

- (void)setDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue
{
	[self setDelegate:newDelegate delegateQueue:newDelegateQueue synchronously:NO];
}

- (void)synchronouslySetDelegate:(id)newDelegate delegateQueue:(dispatch_queue_t)newDelegateQueue
{
	[self setDelegate:newDelegate delegateQueue:newDelegateQueue synchronously:YES];
}

- (BOOL)isIPv4Enabled
{
	// Note: YES means kIPv4Disabled is OFF
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return ((config & kIPv4Disabled) == 0);
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = ((config & kIPv4Disabled) == 0);
		});
		
		return result;
	}
}

- (void)setIPv4Enabled:(BOOL)flag
{
	// Note: YES means kIPv4Disabled is OFF
	
	dispatch_block_t block = ^{
		
		if (flag)
			config &= ~kIPv4Disabled;
		else
			config |= kIPv4Disabled;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}

- (BOOL)isIPv6Enabled
{
	// Note: YES means kIPv6Disabled is OFF
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return ((config & kIPv6Disabled) == 0);
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = ((config & kIPv6Disabled) == 0);
		});
		
		return result;
	}
}

- (void)setIPv6Enabled:(BOOL)flag
{
	// Note: YES means kIPv6Disabled is OFF
	
	dispatch_block_t block = ^{
		
		if (flag)
			config &= ~kIPv6Disabled;
		else
			config |= kIPv6Disabled;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}

- (BOOL)isIPv4PreferredOverIPv6
{
	// Note: YES means kPreferIPv6 is OFF
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return ((config & kPreferIPv6) == 0);
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = ((config & kPreferIPv6) == 0);
		});
		
		return result;
	}
}

- (void)setIPv4PreferredOverIPv6:(BOOL)flag
{
	// Note: YES means kPreferIPv6 is OFF
	
	dispatch_block_t block = ^{
		
		if (flag)
			config &= ~kPreferIPv6;
		else
			config |= kPreferIPv6;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
        //
		dispatch_async(socketQueue, block);
}

//get 同样
- (NSTimeInterval) alternateAddressDelay {
    __block NSTimeInterval delay;
    dispatch_block_t block = ^{
        delay = alternateAddressDelay;
    };
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        //读是用sync方式，在当前线程，阻塞当前线程，也阻塞socketQueue队列
        dispatch_sync(socketQueue, block);
    return delay;
}

//set方法，写这么多就是为了在同一队列，避免线程不安全（串行队列）
- (void) setAlternateAddressDelay:(NSTimeInterval)delay {
    //生成Block
    dispatch_block_t block = ^{
        //设置延迟时间
        alternateAddressDelay = delay;
    };
    //如果当前queue是这个初始化的queue,才执行Block
    if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
        block();
    else
        //否则到这个queue去执行，写是用async，异步线程，串行
        dispatch_async(socketQueue, block);
}

- (id)userData
{
	__block id result = nil;
	
	dispatch_block_t block = ^{
		
		result = userData;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

- (void)setUserData:(id)arbitraryUserData
{
	dispatch_block_t block = ^{
		
		if (userData != arbitraryUserData)
		{
			userData = arbitraryUserData;
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Accepting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//监听端口起点
- (BOOL)acceptOnPort:(uint16_t)port error:(NSError **)errPtr
{
	return [self acceptOnInterface:nil port:port error:errPtr];
}

- (BOOL)acceptOnInterface:(NSString *)inInterface port:(uint16_t)port error:(NSError **)errPtr
{
	LogTrace();
	
	// Just in-case interface parameter is immutable.
    //防止参数被修改
	NSString *interface = [inInterface copy];
	
	__block BOOL result = NO;
	__block NSError *err = nil;
	
	// CreateSocket Block
	// This block will be invoked within the dispatch block below.
	//创建socket的Block
	int(^createSocket)(int, NSData*) = ^int (int domain, NSData *interfaceAddr) {
		
        //创建TCP的socket
		int socketFD = socket(domain, SOCK_STREAM, 0);
		
        //为空错误返回
		if (socketFD == SOCKET_NULL)
		{
			NSString *reason = @"Error in socket() function";
			err = [self errnoErrorWithReason:reason];
			
			return SOCKET_NULL;
		}
		
		int status;
		
		// Set socket options
		//配置socket的可选项
        //设置非阻塞
		status = fcntl(socketFD, F_SETFL, O_NONBLOCK);
        //错误返回
		if (status == -1)
		{
			NSString *reason = @"Error enabling non-blocking IO on socket (fcntl)";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		int reuseOn = 1;
        //设置socket关闭可重用
		status = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
        //错误返回
		if (status == -1)
		{
			NSString *reason = @"Error enabling address reuse (setsockopt)";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		// Bind socket
        //用本地地址去绑定
		status = bind(socketFD, (const struct sockaddr *)[interfaceAddr bytes], (socklen_t)[interfaceAddr length]);
		if (status == -1)
		{
			NSString *reason = @"Error in bind() function";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		// Listen
		//监听这个socket
        //第二个参数是这个端口下维护的socket请求队列，最多容纳的用户请求数。
		status = listen(socketFD, 1024);
		if (status == -1)
		{
			NSString *reason = @"Error in listen() function";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		return socketFD;
	};
	
	// Create dispatch block and run on socketQueue
	
	dispatch_block_t block = ^{ @autoreleasepool {
		
        //代理为空直接返回
		if (delegate == nil) // Must have delegate set
		{
			NSString *msg = @"Attempting to accept without a delegate. Set a delegate first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
        //代理队列为空也返回
		if (delegateQueue == NULL) // Must have delegate queue set
		{
			NSString *msg = @"Attempting to accept without a delegate queue. Set a delegate queue first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
        //判断ipv4 ipv6是否支持
		BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
		BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
		
        //都不支持返回
		if (isIPv4Disabled && isIPv6Disabled) // Must have IPv4 or IPv6 enabled
		{
			NSString *msg = @"Both IPv4 and IPv6 have been disabled. Must enable at least one protocol first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
        //已连接返回
		if (![self isDisconnected]) // Must be disconnected
		{
			NSString *msg = @"Attempting to accept while connected or accepting connections. Disconnect first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
        //清除读写queue
		// Clear queues (spurious read/write requests post disconnect)
		[readQueue removeAllObjects];
		[writeQueue removeAllObjects];
		
		// Resolve interface from description
		
		NSMutableData *interface4 = nil;
		NSMutableData *interface6 = nil;
		
        //得到本机的IPV4 IPV6的地址
		[self getInterfaceAddress4:&interface4 address6:&interface6 fromDescription:interface port:port];
		//错误判断
		if ((interface4 == nil) && (interface6 == nil))
		{
			NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		if (isIPv4Disabled && (interface6 == nil))
		{
			NSString *msg = @"IPv4 has been disabled and specified interface doesn't support IPv6.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		if (isIPv6Disabled && (interface4 == nil))
		{
			NSString *msg = @"IPv6 has been disabled and specified interface doesn't support IPv4.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
        //判断可以用IPV4还是6进行请求
		BOOL enableIPv4 = !isIPv4Disabled && (interface4 != nil);
		BOOL enableIPv6 = !isIPv6Disabled && (interface6 != nil);
		
		// Create sockets, configure, bind, and listen
		//用我们之前的Block去创建、绑定、监听。
		if (enableIPv4)
		{
			LogVerbose(@"Creating IPv4 socket");
			socket4FD = createSocket(AF_INET, interface4);
			
			if (socket4FD == SOCKET_NULL)
			{
				return_from_block;
			}
		}
		
        //IPV6
		if (enableIPv6)
		{
			LogVerbose(@"Creating IPv6 socket");
			//判断如果Port为0
			if (enableIPv4 && (port == 0))
			{
				// No specific port was specified, so we allowed the OS to pick an available port for us.
				// Now we need to make sure the IPv6 socket listens on the same port as the IPv4 socket.
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)[interface6 mutableBytes];
                //就用IPV4的Port

				addr6->sin6_port = htons([self localPort4]);
			}
			
            //创建IPV6 socket
			socket6FD = createSocket(AF_INET6, interface6);
			
			if (socket6FD == SOCKET_NULL)
			{
				if (socket4FD != SOCKET_NULL)
				{
					LogVerbose(@"close(socket4FD)");
					close(socket4FD);
				}
				
				return_from_block;
			}
		}
		
		// Create accept sources
		//创建接受连接的source
		if (enableIPv4)
		{
            //读source?
			accept4Source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socket4FD, 0, socketQueue);
			
			int socketFD = socket4FD;
			dispatch_source_t acceptSource = accept4Source;
			
			__weak GCDAsyncSocket *weakSelf = self;
			
            //事件句柄
			dispatch_source_set_event_handler(accept4Source, ^{ @autoreleasepool {
			#pragma clang diagnostic push
			#pragma clang diagnostic warning "-Wimplicit-retain-self"
				
				__strong GCDAsyncSocket *strongSelf = weakSelf;
				if (strongSelf == nil) return_from_block;
				
				LogVerbose(@"event4Block");
				
				unsigned long i = 0;
                //拿到数据，连接数
				unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
				
				LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
				
                //循环去接受这些socket的事件
				while ([strongSelf doAccept:socketFD] && (++i < numPendingConnections));
				
			#pragma clang diagnostic pop
			}});
			
			//取消句柄
			dispatch_source_set_cancel_handler(accept4Source, ^{
			#pragma clang diagnostic push
			#pragma clang diagnostic warning "-Wimplicit-retain-self"
				
				#if !OS_OBJECT_USE_OBJC
				LogVerbose(@"dispatch_release(accept4Source)");
				dispatch_release(acceptSource);
				#endif
				
				LogVerbose(@"close(socket4FD)");
                //关闭socket
				close(socketFD);
			
			#pragma clang diagnostic pop
			});
			
			LogVerbose(@"dispatch_resume(accept4Source)");
            //开启source
			dispatch_resume(accept4Source);
		}
		
        //ipv6一样
		if (enableIPv6)
		{
			accept6Source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socket6FD, 0, socketQueue);
			
			int socketFD = socket6FD;
			dispatch_source_t acceptSource = accept6Source;
			
			__weak GCDAsyncSocket *weakSelf = self;
			
			dispatch_source_set_event_handler(accept6Source, ^{ @autoreleasepool {
			#pragma clang diagnostic push
			#pragma clang diagnostic warning "-Wimplicit-retain-self"
				
				__strong GCDAsyncSocket *strongSelf = weakSelf;
				if (strongSelf == nil) return_from_block;
				
				LogVerbose(@"event6Block");
				
				unsigned long i = 0;
				unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
				
				LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
				
				while ([strongSelf doAccept:socketFD] && (++i < numPendingConnections));
				
			#pragma clang diagnostic pop
			}});
			
			dispatch_source_set_cancel_handler(accept6Source, ^{
			#pragma clang diagnostic push
			#pragma clang diagnostic warning "-Wimplicit-retain-self"
				
				#if !OS_OBJECT_USE_OBJC
				LogVerbose(@"dispatch_release(accept6Source)");
				dispatch_release(acceptSource);
				#endif
				
				LogVerbose(@"close(socket6FD)");
				close(socketFD);
				
			#pragma clang diagnostic pop
			});
			
			LogVerbose(@"dispatch_resume(accept6Source)");
			dispatch_resume(accept6Source);
		}
		
        //标记socket开始
		flags |= kSocketStarted;
		//结果正常
		result = YES;
	}};
	
    //在scoketQueue中同步做这些初始化。
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
    //结果为NO填充错误
	if (result == NO)
	{
		LogInfo(@"Error in accept: %@", err);
		
		if (errPtr)
			*errPtr = err;
	}
	//返回结果
	return result;
}

//接受一个Url，uniex domin socket 做为服务端
- (BOOL)acceptOnUrl:(NSURL *)url error:(NSError **)errPtr;
{
	LogTrace();
	
	__block BOOL result = NO;
	__block NSError *err = nil;
	
    //基本和正常的socket accept一模一样
	// CreateSocket Block
	// This block will be invoked within the dispatch block below.
	//生成一个创建socket的block，创建、绑定、监听
	int(^createSocket)(int, NSData*) = ^int (int domain, NSData *interfaceAddr) {
		
		int socketFD = socket(domain, SOCK_STREAM, 0);
		
		if (socketFD == SOCKET_NULL)
		{
			NSString *reason = @"Error in socket() function";
			err = [self errnoErrorWithReason:reason];
			
			return SOCKET_NULL;
		}
		
		int status;
		
		// Set socket options
		status = fcntl(socketFD, F_SETFL, O_NONBLOCK);
		if (status == -1)
		{
			NSString *reason = @"Error enabling non-blocking IO on socket (fcntl)";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		int reuseOn = 1;
		status = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
		if (status == -1)
		{
			NSString *reason = @"Error enabling address reuse (setsockopt)";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		// Bind socket
		
		status = bind(socketFD, (const struct sockaddr *)[interfaceAddr bytes], (socklen_t)[interfaceAddr length]);
		if (status == -1)
		{
			NSString *reason = @"Error in bind() function";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		// Listen
		
		status = listen(socketFD, 1024);
		if (status == -1)
		{
			NSString *reason = @"Error in listen() function";
			err = [self errnoErrorWithReason:reason];
			
			LogVerbose(@"close(socketFD)");
			close(socketFD);
			return SOCKET_NULL;
		}
		
		return socketFD;
	};
	
	// Create dispatch block and run on socketQueue
	//错误判断
	dispatch_block_t block = ^{ @autoreleasepool {
		
		if (delegate == nil) // Must have delegate set
		{
			NSString *msg = @"Attempting to accept without a delegate. Set a delegate first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		if (delegateQueue == NULL) // Must have delegate queue set
		{
			NSString *msg = @"Attempting to accept without a delegate queue. Set a delegate queue first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		if (![self isDisconnected]) // Must be disconnected
		{
			NSString *msg = @"Attempting to accept while connected or accepting connections. Disconnect first.";
			err = [self badConfigError:msg];
			
			return_from_block;
		}
		
		// Clear queues (spurious read/write requests post disconnect)
		[readQueue removeAllObjects];
		[writeQueue removeAllObjects];
		
		// Remove a previous socket
		
		NSError *error = nil;
		NSFileManager *fileManager = [NSFileManager defaultManager];
        //判断是否有这个文件路径
		if ([fileManager fileExistsAtPath:url.path]) {
            //移除文件
			if (![[NSFileManager defaultManager] removeItemAtURL:url error:&error]) {
                //移除失败报错
				NSString *msg = @"Could not remove previous unix domain socket at given url.";
				err = [self otherError:msg];
				
				return_from_block;
			}
		}
		
		// Resolve interface from description
		//拿到地址
		NSData *interface = [self getInterfaceAddressFromUrl:url];
		//错误返回
		if (interface == nil)
		{
			NSString *msg = @"Invalid unix domain url. Specify a valid file url that does not exist (e.g. \"file:///tmp/socket\")";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		// Create sockets, configure, bind, and listen
		
		LogVerbose(@"Creating unix domain socket");
        //UnixSocket
        //创建socket，并且绑定监听。
		socketUN = createSocket(AF_UNIX, interface);
		
		if (socketUN == SOCKET_NULL)
		{
			return_from_block;
		}
		//url也赋值
		socketUrl = url;
		
		// Create accept sources
		
        //创建接受连接的sorce
		acceptUNSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socketUN, 0, socketQueue);
		
		int socketFD = socketUN;
		dispatch_source_t acceptSource = acceptUNSource;
		//事件句柄，和accpept一样
		dispatch_source_set_event_handler(acceptUNSource, ^{ @autoreleasepool {
			
			LogVerbose(@"eventUNBlock");
			
			unsigned long i = 0;
			unsigned long numPendingConnections = dispatch_source_get_data(acceptSource);
			
			LogVerbose(@"numPendingConnections: %lu", numPendingConnections);
			
			while ([self doAccept:socketFD] && (++i < numPendingConnections));
		}});
		
        //取消句柄
		dispatch_source_set_cancel_handler(acceptUNSource, ^{
			
#if NEEDS_DISPATCH_RETAIN_RELEASE
			LogVerbose(@"dispatch_release(accept4Source)");
			dispatch_release(acceptSource);
#endif
			
			LogVerbose(@"close(socket4FD)");
			close(socketFD);
		});
		
		LogVerbose(@"dispatch_resume(accept4Source)");
		dispatch_resume(acceptUNSource);
		
		flags |= kSocketStarted;
		
		result = YES;
	}};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	if (result == NO)
	{
		LogInfo(@"Error in accept: %@", err);
		
		if (errPtr)
			*errPtr = err;
	}
	
	return result;	
}

//连接接受的方法
- (BOOL)doAccept:(int)parentSocketFD
{
	LogTrace();
	
	int socketType;
	int childSocketFD;
	NSData *childSocketAddress;
	
    //IPV4
	if (parentSocketFD == socket4FD)
	{
		socketType = 0;
		
		struct sockaddr_in addr;
		socklen_t addrLen = sizeof(addr);
		//调用接受，得到接受的子socket
		childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
		//NO说明没有连接
		if (childSocketFD == -1)
		{
			LogWarn(@"Accept failed with error: %@", [self errnoError]);
			return NO;
		}
		//子socket的地址数据
		childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
	}
    //一样
	else if (parentSocketFD == socket6FD)
	{
		socketType = 1;
		
		struct sockaddr_in6 addr;
		socklen_t addrLen = sizeof(addr);
		
		childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
		
		if (childSocketFD == -1)
		{
			LogWarn(@"Accept failed with error: %@", [self errnoError]);
			return NO;
		}
		
		childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
	}
    //unix domin socket
	else // if (parentSocketFD == socketUN)
	{
		socketType = 2;
		
		struct sockaddr_un addr;
		socklen_t addrLen = sizeof(addr);
		
		childSocketFD = accept(parentSocketFD, (struct sockaddr *)&addr, &addrLen);
		
		if (childSocketFD == -1)
		{
			LogWarn(@"Accept failed with error: %@", [self errnoError]);
			return NO;
		}
		
		childSocketAddress = [NSData dataWithBytes:&addr length:addrLen];
	}
	
	// Enable non-blocking IO on the socket
	//设置IO 非阻塞
	int result = fcntl(childSocketFD, F_SETFL, O_NONBLOCK);
	if (result == -1)
	{
		LogWarn(@"Error enabling non-blocking IO on accepted socket (fcntl)");
		return NO;
	}
	
	// Prevent SIGPIPE signals
	
	int nosigpipe = 1;
    //防止错误信号导致进程关闭
	setsockopt(childSocketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
	
	// Notify delegate
	
    //响应代理
	if (delegateQueue)
	{
		__strong id theDelegate = delegate;
		//代理队列中调用
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			// Query delegate for custom socket queue
			
			dispatch_queue_t childSocketQueue = NULL;
			
            //判断是否实现了为socket 生成一个新的SocketQueue，是的话拿到新queue
			if ([theDelegate respondsToSelector:@selector(newSocketQueueForConnectionFromAddress:onSocket:)])
			{
				childSocketQueue = [theDelegate newSocketQueueForConnectionFromAddress:childSocketAddress
				                                                              onSocket:self];
			}
			
			// Create GCDAsyncSocket instance for accepted socket
			//新创建一个本类实例，给接受的socket
			GCDAsyncSocket *acceptedSocket = [[[self class] alloc] initWithDelegate:theDelegate
																	  delegateQueue:delegateQueue
																		socketQueue:childSocketQueue];
			//IPV4 6 un
			if (socketType == 0)
				acceptedSocket->socket4FD = childSocketFD;
			else if (socketType == 1)
				acceptedSocket->socket6FD = childSocketFD;
			else
				acceptedSocket->socketUN = childSocketFD;
			//标记开始 并且已经连接
			acceptedSocket->flags = (kSocketStarted | kConnected);
			
			// Setup read and write sources for accepted socket
			//初始化读写source
			dispatch_async(acceptedSocket->socketQueue, ^{ @autoreleasepool {
				
				[acceptedSocket setupReadAndWriteSourcesForNewlyConnectedSocket:childSocketFD];
			}});
			
			// Notify delegate
			
            //判断代理是否实现了didAcceptNewSocket方法，把我们新创建的socket返回出去
			if ([theDelegate respondsToSelector:@selector(socket:didAcceptNewSocket:)])
			{
				[theDelegate socket:self didAcceptNewSocket:acceptedSocket];
			}
			
			// Release the socket queue returned from the delegate (it was retained by acceptedSocket)
			#if !OS_OBJECT_USE_OBJC
			if (childSocketQueue) dispatch_release(childSocketQueue);
			#endif
			
			// The accepted socket should have been retained by the delegate.
			// Otherwise it gets properly released when exiting the block.
		}});
	}
	
	return YES;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark - --------------------Connect---------------------------------
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/**
 * This method runs through the various checks required prior to a connection attempt.
 * It is shared between the connectToHost and connectToAddress methods.
 * 
**/
//在连接之前的接口检查，一般我们传nil  interface本机的IP 端口等等
- (BOOL)preConnectWithInterface:(NSString *)interface error:(NSError **)errPtr
{
    //先断言，如果当前的queue不是初始化quueue，直接报错
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
    //无代理
	if (delegate == nil) // Must have delegate set
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect without a delegate. Set a delegate first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	//没有代理queue
	if (delegateQueue == NULL) // Must have delegate queue set
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect without a delegate queue. Set a delegate queue first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
    //当前不是非连接状态
	if (![self isDisconnected]) // Must be disconnected
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect while connected or accepting connections. Disconnect first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
    //判断是否支持IPV4 IPV6  &位与运算，因为枚举是用  左位移<<运算定义的，所以可以用来判断 config包不包含某个枚举。因为一个值可能包含好几个枚举值，所以这时候不能用==来判断，只能用&来判断
	BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
	BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
	
    //是否都不支持
	if (isIPv4Disabled && isIPv6Disabled) // Must have IPv4 or IPv6 enabled
	{
		if (errPtr)
		{
			NSString *msg = @"Both IPv4 and IPv6 have been disabled. Must enable at least one protocol first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
    //如果有interface，本机地址
	if (interface)
	{
		NSMutableData *interface4 = nil;
		NSMutableData *interface6 = nil;
		
        //得到本机的IPV4 IPV6地址
		[self getInterfaceAddress4:&interface4 address6:&interface6 fromDescription:interface port:0];
		
        //如果两者都为nil
		if ((interface4 == nil) && (interface6 == nil))
		{
			if (errPtr)
			{
				NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
				*errPtr = [self badParamError:msg];
			}
			return NO;
		}
		
		if (isIPv4Disabled && (interface6 == nil))
		{
			if (errPtr)
			{
				NSString *msg = @"IPv4 has been disabled and specified interface doesn't support IPv6.";
				*errPtr = [self badParamError:msg];
			}
			return NO;
		}
		
		if (isIPv6Disabled && (interface4 == nil))
		{
			if (errPtr)
			{
				NSString *msg = @"IPv6 has been disabled and specified interface doesn't support IPv4.";
				*errPtr = [self badParamError:msg];
			}
			return NO;
		}
		//如果都没问题，则赋值
		connectInterface4 = interface4;
		connectInterface6 = interface6;
	}
	
	// Clear queues (spurious read/write requests post disconnect)
    //清除queue（假的读写请求 ，提交断开连接）
    //读写Queue清除
	[readQueue removeAllObjects];
	[writeQueue removeAllObjects];
	
	return YES;
}

//前置的检查
- (BOOL)preConnectWithUrl:(NSURL *)url error:(NSError **)errPtr
{
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	if (delegate == nil) // Must have delegate set
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect without a delegate. Set a delegate first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
	if (delegateQueue == NULL) // Must have delegate queue set
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect without a delegate queue. Set a delegate queue first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
	if (![self isDisconnected]) // Must be disconnected
	{
		if (errPtr)
		{
			NSString *msg = @"Attempting to connect while connected or accepting connections. Disconnect first.";
			*errPtr = [self badConfigError:msg];
		}
		return NO;
	}
	
    //从Url中拿到 地址结构体 DATA
	NSData *interface = [self getInterfaceAddressFromUrl:url];
	
	if (interface == nil)
	{
		if (errPtr)
		{
			NSString *msg = @"Unknown interface. Specify valid interface by name (e.g. \"en1\") or IP address.";
			*errPtr = [self badParamError:msg];
		}
		return NO;
	}
	//赋值地址
	connectInterfaceUN = interface;
	
	// Clear queues (spurious read/write requests post disconnect)
	[readQueue removeAllObjects];
	[writeQueue removeAllObjects];
	
	return YES;
}

//逐级调用
- (BOOL)connectToHost:(NSString*)host onPort:(uint16_t)port error:(NSError **)errPtr
{
	return [self connectToHost:host onPort:port withTimeout:-1 error:errPtr];
}

- (BOOL)connectToHost:(NSString *)host
               onPort:(uint16_t)port
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr
{
	return [self connectToHost:host onPort:port viaInterface:nil withTimeout:timeout error:errPtr];
}

//多一个inInterface，本机地址
- (BOOL)connectToHost:(NSString *)inHost
               onPort:(uint16_t)port
         viaInterface:(NSString *)inInterface
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr
{
    //{} ？？有什么意义？
	LogTrace();
	
	// Just in case immutable objects were passed
    //拿到host ,copy防止值被修改
	NSString *host = [inHost copy];
    //interface？接口？
	NSString *interface = [inInterface copy];
	
    //声明两个__block的
	__block BOOL result = NO;
    //error信息
	__block NSError *preConnectErr = nil;
	
    //gcdBlock ,都包裹在自动释放池中
	dispatch_block_t block = ^{ @autoreleasepool {
		
		// Check for problems with host parameter
		
		if ([host length] == 0)
		{
			NSString *msg = @"Invalid host parameter (nil or \"\"). Should be a domain name or IP address string.";
			preConnectErr = [self badParamError:msg];
			
            //其实就是return,大牛的代码真是充满逼格
			return_from_block;
		}
		
		// Run through standard pre-connect checks
		//一个前置的检查,如果没通过返回，这个检查里，如果interface有值，则会将本机的IPV4 IPV6的 address设置上。
		if (![self preConnectWithInterface:interface error:&preConnectErr])
		{
			return_from_block;
		}
		
		// We've made it past all the checks.
		// It's time to start the connection process.
		//flags 做或等运算。 flags标识为开始Socket连接
		flags |= kSocketStarted;
        
        //又是一个{}? 只是为了标记么？
		LogVerbose(@"Dispatching DNS lookup...");
		
		// It's possible that the given host parameter is actually a NSMutableString.
        //很可能给我们的服务端的参数是一个可变字符串
		// So we want to copy it now, within this block that will be executed synchronously.
        //所以我们需要copy，在Block里同步的执行
		// This way the asynchronous lookup block below doesn't have to worry about it changing.
		//这种基于Block的异步查找，不需要担心它被改变
        
        //copy，防止改变
		NSString *hostCpy = [host copy];
		
        //拿到状态
		int aStateIndex = stateIndex;
		__weak GCDAsyncSocket *weakSelf = self;
		
        //全局Queue
		dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        //异步执行
		dispatch_async(globalConcurrentQueue, ^{ @autoreleasepool {
            //忽视循环引用
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
            //查找错误
			NSError *lookupErr = nil;
            //server地址数组（包含IPV4 IPV6的地址  sockaddr_in6、sockaddr_in类型）
			NSMutableArray *addresses = [[self class] lookupHost:hostCpy port:port error:&lookupErr];
			
            //strongSelf
			__strong GCDAsyncSocket *strongSelf = weakSelf;
            
            //完整Block安全形态，在加个if
			if (strongSelf == nil) return_from_block;
			
            //如果有错
			if (lookupErr)
			{
                //用cocketQueue
				dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
					//一些错误处理，清空一些数据等等
					[strongSelf lookup:aStateIndex didFail:lookupErr];
				}});
			}
            //正常
			else
			{
                
				NSData *address4 = nil;
				NSData *address6 = nil;
				//遍历地址数组
				for (NSData *address in addresses)
				{
                    //判断address4为空，且address为IPV4
					if (!address4 && [[self class] isIPv4Address:address])
					{
						address4 = address;
					}
                    //判断address6为空，且address为IPV6
					else if (!address6 && [[self class] isIPv6Address:address])
					{
						address6 = address;
					}
				}
				//异步去发起连接
				dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
					
					[strongSelf lookup:aStateIndex didSucceedWithAddress4:address4 address6:address6];
				}});
			}
			
		#pragma clang diagnostic pop
		}});
        
        
		//开启连接超时
		[self startConnectTimeout:timeout];
		
		result = YES;
	}};
	//在socketQueue中执行这个Block
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
    //否则同步的调起这个queue去执行
	else
		dispatch_sync(socketQueue, block);
	
	//如果有错误，赋值错误
	if (errPtr) *errPtr = preConnectErr;
    //把连接是否成功的result返回
	return result;
}

//直接连接到一个addr的data
- (BOOL)connectToAddress:(NSData *)remoteAddr error:(NSError **)errPtr
{
	return [self connectToAddress:remoteAddr viaInterface:nil withTimeout:-1 error:errPtr];
}

- (BOOL)connectToAddress:(NSData *)remoteAddr withTimeout:(NSTimeInterval)timeout error:(NSError **)errPtr
{
	return [self connectToAddress:remoteAddr viaInterface:nil withTimeout:timeout error:errPtr];
}

- (BOOL)connectToAddress:(NSData *)inRemoteAddr
            viaInterface:(NSString *)inInterface
             withTimeout:(NSTimeInterval)timeout
                   error:(NSError **)errPtr
{
	LogTrace();
	
	// Just in case immutable objects were passed
	NSData *remoteAddr = [inRemoteAddr copy];
	NSString *interface = [inInterface copy];
	
	__block BOOL result = NO;
	__block NSError *err = nil;
	
	dispatch_block_t block = ^{ @autoreleasepool {
		
		// Check for problems with remoteAddr parameter
		
		NSData *address4 = nil;
		NSData *address6 = nil;
		
		if ([remoteAddr length] >= sizeof(struct sockaddr))
		{
			const struct sockaddr *sockaddr = (const struct sockaddr *)[remoteAddr bytes];
			
			if (sockaddr->sa_family == AF_INET)
			{
				if ([remoteAddr length] == sizeof(struct sockaddr_in))
				{
					address4 = remoteAddr;
				}
			}
			else if (sockaddr->sa_family == AF_INET6)
			{
				if ([remoteAddr length] == sizeof(struct sockaddr_in6))
				{
					address6 = remoteAddr;
				}
			}
		}
		
		if ((address4 == nil) && (address6 == nil))
		{
			NSString *msg = @"A valid IPv4 or IPv6 address was not given";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
		BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
		
		if (isIPv4Disabled && (address4 != nil))
		{
			NSString *msg = @"IPv4 has been disabled and an IPv4 address was passed.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		if (isIPv6Disabled && (address6 != nil))
		{
			NSString *msg = @"IPv6 has been disabled and an IPv6 address was passed.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		// Run through standard pre-connect checks
		
		if (![self preConnectWithInterface:interface error:&err])
		{
			return_from_block;
		}
		
		// We've made it past all the checks.
		// It's time to start the connection process.
		
		if (![self connectWithAddress4:address4 address6:address6 error:&err])
		{
			return_from_block;
		}
		
		flags |= kSocketStarted;
		
		[self startConnectTimeout:timeout];
		
		result = YES;
	}};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	if (result == NO)
	{
		if (errPtr)
			*errPtr = err;
	}
	
	return result;
}

//连接本机的url上，IPC，进程间通信
- (BOOL)connectToUrl:(NSURL *)url withTimeout:(NSTimeInterval)timeout error:(NSError **)errPtr;
{
	LogTrace();
	
	__block BOOL result = NO;
	__block NSError *err = nil;
	
	dispatch_block_t block = ^{ @autoreleasepool {
		
		//判断长度
		if ([url.path length] == 0)
		{
			NSString *msg = @"Invalid unix domain socket url.";
			err = [self badParamError:msg];
			
			return_from_block;
		}
		
		// Run through standard pre-connect checks
		//前置的检查
		if (![self preConnectWithUrl:url error:&err])
		{
			return_from_block;
		}
		
		// We've made it past all the checks.
		// It's time to start the connection process.
		
		flags |= kSocketStarted;
		
		// Start the normal connection process
		
		NSError *connectError = nil;
        //调用另一个方法去连接
		if (![self connectWithAddressUN:connectInterfaceUN error:&connectError])
		{
			[self closeWithError:connectError];
			
			return_from_block;
		}

		[self startConnectTimeout:timeout];
		
		result = YES;
	}};
	
    //在socketQueue中同步执行
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	if (result == NO)
	{
		if (errPtr)
			*errPtr = err;
	}
	
	return result;
}

//连接的最终方法 1
- (void)lookup:(int)aStateIndex didSucceedWithAddress4:(NSData *)address4 address6:(NSData *)address6
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    //至少有一个server地址
	NSAssert(address4 || address6, @"Expected at least one valid address");
	
    //如果状态不一致，说明断开连接
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring lookupDidSucceed, already disconnected");
		
		// The connect operation has been cancelled.
		// That is, socket was disconnected, or connection has already timed out.
		return;
	}
	
	// Check for problems
	//分开判断。
	BOOL isIPv4Disabled = (config & kIPv4Disabled) ? YES : NO;
	BOOL isIPv6Disabled = (config & kIPv6Disabled) ? YES : NO;
	
	if (isIPv4Disabled && (address6 == nil))
	{
		NSString *msg = @"IPv4 has been disabled and DNS lookup found no IPv6 address.";
		
		[self closeWithError:[self otherError:msg]];
		return;
	}
	
	if (isIPv6Disabled && (address4 == nil))
	{
		NSString *msg = @"IPv6 has been disabled and DNS lookup found no IPv4 address.";
		
		[self closeWithError:[self otherError:msg]];
		return;
	}
	
	// Start the normal connection process
	
	NSError *err = nil;
    //调用连接方法，如果失败，则错误返回
	if (![self connectWithAddress4:address4 address6:address6 error:&err])
	{
		[self closeWithError:err];
	}
}

/**
 * This method is called if the DNS lookup fails.
 * This method is executed on the socketQueue.
 * 
 * Since the DNS lookup executed synchronously on a global concurrent queue,
 * the original connection request may have already been cancelled or timed-out by the time this method is invoked.
 * The lookupIndex tells us whether the lookup is still valid or not.
**/
- (void)lookup:(int)aStateIndex didFail:(NSError *)error
{
	LogTrace();
	
    //先判断是不是socketQueue
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	//如果传进来的状态和当前状态不一样，说明已经断开连接
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring lookup:didFail: - already disconnected");
		
		// The connect operation has been cancelled.
		// That is, socket was disconnected, or connection has already timed out.
		return;
	}
	
    //出错就先关闭连接超时，清空一些参数
	[self endConnectTimeout];
    //根据error去关闭...
	[self closeWithError:error];
}

//绑定一个Socket的本地地址
- (BOOL)bindSocket:(int)socketFD toInterface:(NSData *)connectInterface error:(NSError **)errPtr
{
    // Bind the socket to the desired interface (if needed)
    //无接口就不绑定，connect会自动绑定到一个不冲突的端口上去。
    if (connectInterface)
    {
        LogVerbose(@"Binding socket...");
        
        //判断当前地址的Port是不是大于0
        if ([[self class] portFromAddress:connectInterface] > 0)
        {
            // Since we're going to be binding to a specific port,
            // we should turn on reuseaddr to allow us to override sockets in time_wait.
            
            int reuseOn = 1;
            
            
            //设置调用close(socket)后,仍可继续重用该socket。调用close(socket)一般不会立即关闭socket，而经历TIME_WAIT的过程。
            setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
        }
        
        //拿到地址
        const struct sockaddr *interfaceAddr = (const struct sockaddr *)[connectInterface bytes];
        //绑定这个地址
        int result = bind(socketFD, interfaceAddr, (socklen_t)[connectInterface length]);
        
        //绑定出错，返回NO
        if (result != 0)
        {
            if (errPtr)
                *errPtr = [self errnoErrorWithReason:@"Error in bind() function"];
            
            return NO;
        }
    }
    
    //成功
    return YES;
}


//创建Socket
- (int)createSocket:(int)family connectInterface:(NSData *)connectInterface errPtr:(NSError **)errPtr
{
    //创建socket,用的SOCK_STREAM TCP流
    int socketFD = socket(family, SOCK_STREAM, 0);
    //如果创建失败
    if (socketFD == SOCKET_NULL)
    {
        if (errPtr)
            *errPtr = [self errnoErrorWithReason:@"Error in socket() function"];
        
        return socketFD;
    }
    
    //和connectInterface绑定
    if (![self bindSocket:socketFD toInterface:connectInterface error:errPtr])
    {
        //绑定失败，直接关闭返回
        [self closeSocket:socketFD];
        
        return SOCKET_NULL;
    }
    
    // Prevent SIGPIPE signals
    //防止终止进程的信号？
    int nosigpipe = 1;
    //SO_NOSIGPIPE是为了避免网络错误，而导致进程退出。用这个来避免系统发送signal
    setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
    
    return socketFD;
}

//连接最终方法 3 finnal。。。
- (void)connectSocket:(int)socketFD address:(NSData *)address stateIndex:(int)aStateIndex
{
    // If there already is a socket connected, we close socketFD and return
    //已连接，关闭连接返回
    if (self.isConnected)
    {
        [self closeSocket:socketFD];
        return;
    }
    
    // Start the connection process in a background queue
    //开始连接过程，在后台queue中
    __weak GCDAsyncSocket *weakSelf = self;
    
    //获取到全局Queue
    dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    //新线程
    dispatch_async(globalConcurrentQueue, ^{
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wimplicit-retain-self"
        //调用connect方法，该函数阻塞线程，所以要异步新线程
        //客户端向特定网络地址的服务器发送连接请求，连接成功返回0，失败返回 -1。
        int result = connect(socketFD, (const struct sockaddr *)[address bytes], (socklen_t)[address length]);
        
        //老样子，安全判断
        __strong GCDAsyncSocket *strongSelf = weakSelf;
        if (strongSelf == nil) return_from_block;
        
        //在socketQueue中，开辟线程
        dispatch_async(strongSelf->socketQueue, ^{ @autoreleasepool {
            //如果状态为已经连接，关闭连接返回
            if (strongSelf.isConnected)
            {
                [strongSelf closeSocket:socketFD];
                return_from_block;
            }
            
            //说明连接成功
            if (result == 0)
            {
                //关闭掉另一个没用的socket
                [self closeUnusedSocket:socketFD];
                //调用didConnect，生成stream，改变状态等等！
                [strongSelf didConnect:aStateIndex];
            }
            //连接失败
            else
            {
                //关闭当前socket
                [strongSelf closeSocket:socketFD];
                
                // If there are no more sockets trying to connect, we inform the error to the delegate
                //返回连接错误的error
                if (strongSelf.socket4FD == SOCKET_NULL && strongSelf.socket6FD == SOCKET_NULL)
                {
                    NSError *error = [strongSelf errnoErrorWithReason:@"Error in connect() function"];
                    [strongSelf didNotConnect:aStateIndex error:error];
                }
            }
        }});
        
#pragma clang diagnostic pop
    });
    //输出正在连接中
    LogVerbose(@"Connecting...");
}

//关闭socket
- (void)closeSocket:(int)socketFD
{
    if (socketFD != SOCKET_NULL &&
        (socketFD == socket6FD || socketFD == socket4FD))
    {
        close(socketFD);
        
        if (socketFD == socket4FD)
        {
            LogVerbose(@"close(socket4FD)");
            socket4FD = SOCKET_NULL;
        }
        else if (socketFD == socket6FD)
        {
            LogVerbose(@"close(socket6FD)");
            socket6FD = SOCKET_NULL;
        }
    }
}
//关闭另一个没用的socket
- (void)closeUnusedSocket:(int)usedSocketFD
{
    if (usedSocketFD != socket4FD)
    {
        [self closeSocket:socket4FD];
    }
    else if (usedSocketFD != socket6FD)
    {
        [self closeSocket:socket6FD];
    }
}

//连接最终方法 2。用两个Server地址去连接，失败返回NO，并填充error
- (BOOL)connectWithAddress4:(NSData *)address4 address6:(NSData *)address6 error:(NSError **)errPtr
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
    //输出一些东西？
	LogVerbose(@"IPv4: %@:%hu", [[self class] hostFromAddress:address4], [[self class] portFromAddress:address4]);
	LogVerbose(@"IPv6: %@:%hu", [[self class] hostFromAddress:address6], [[self class] portFromAddress:address6]);
	
	// Determine socket type
	
    //判断是否倾向于IPV6
	BOOL preferIPv6 = (config & kPreferIPv6) ? YES : NO;
	
	// Create and bind the sockets
    
    //如果有IPV4地址，创建IPV4 Socket
    if (address4)
    {
        LogVerbose(@"Creating IPv4 socket");
        
        socket4FD = [self createSocket:AF_INET connectInterface:connectInterface4 errPtr:errPtr];
    }
    //如果有IPV6地址，创建IPV6 Socket
    if (address6)
    {
        LogVerbose(@"Creating IPv6 socket");
        
        socket6FD = [self createSocket:AF_INET6 connectInterface:connectInterface6 errPtr:errPtr];
    }
    
    //如果都为空，直接返回
    if (socket4FD == SOCKET_NULL && socket6FD == SOCKET_NULL)
    {
        return NO;
    }
	
    //主选socketFD,备选alternateSocketFD
	int socketFD, alternateSocketFD;
    //主选地址和备选地址
	NSData *address, *alternateAddress;
	
    //IPV6
    if ((preferIPv6 && socket6FD) || socket4FD == SOCKET_NULL)
    {
        socketFD = socket6FD;
        alternateSocketFD = socket4FD;
        address = address6;
        alternateAddress = address4;
    }
    //主选IPV4
    else
    {
        socketFD = socket4FD;
        alternateSocketFD = socket6FD;
        address = address4;
        alternateAddress = address6;
    }
    //拿到当前状态
    int aStateIndex = stateIndex;
    //用socket和address去连接
    [self connectSocket:socketFD address:address stateIndex:aStateIndex];
    
    //如果有备选地址
    if (alternateAddress)
    {
        //延迟去连接备选的地址
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(alternateAddressDelay * NSEC_PER_SEC)), socketQueue, ^{
            [self connectSocket:alternateSocketFD address:alternateAddress stateIndex:aStateIndex];
        });
    }
	
	return YES;
}

//连接Unix域服务器
- (BOOL)connectWithAddressUN:(NSData *)address error:(NSError **)errPtr
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	// Create the socket
	
	int socketFD;
	
	LogVerbose(@"Creating unix domain socket");
	
    //创建本机socket
	socketUN = socket(AF_UNIX, SOCK_STREAM, 0);
	
	socketFD = socketUN;
	
	if (socketFD == SOCKET_NULL)
	{
		if (errPtr)
			*errPtr = [self errnoErrorWithReason:@"Error in socket() function"];
		
		return NO;
	}
	
	// Bind the socket to the desired interface (if needed)
	
	LogVerbose(@"Binding socket...");
	
	int reuseOn = 1;
    //设置可复用
	setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));

//	const struct sockaddr *interfaceAddr = (const struct sockaddr *)[address bytes];
//	
//	int result = bind(socketFD, interfaceAddr, (socklen_t)[address length]);
//	if (result != 0)
//	{
//		if (errPtr)
//			*errPtr = [self errnoErrorWithReason:@"Error in bind() function"];
//		
//		return NO;
//	}
	
	// Prevent SIGPIPE signals
	
	int nosigpipe = 1;
    //进程终止错误信号禁止
	setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
	
	// Start the connection process in a background queue
	
	int aStateIndex = stateIndex;
	
	dispatch_queue_t globalConcurrentQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
	dispatch_async(globalConcurrentQueue, ^{
		
		const struct sockaddr *addr = (const struct sockaddr *)[address bytes];
        //并行队列调用连接
		int result = connect(socketFD, addr, addr->sa_len);
		if (result == 0)
		{
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				//连接成功的一些状态初始化
				[self didConnect:aStateIndex];
			}});
		}
		else
		{
			// 失败的处理
			perror("connect");
			NSError *error = [self errnoErrorWithReason:@"Error in connect() function"];
			
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				[self didNotConnect:aStateIndex error:error];
			}});
		}
	});
	
	LogVerbose(@"Connecting...");
	
	return YES;
}

//连接成功后调用，设置一些连接成功的状态
- (void)didConnect:(int)aStateIndex
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	//状态不同
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring didConnect, already disconnected");
		
		// The connect operation has been cancelled.
		// That is, socket was disconnected, or connection has already timed out.
		return;
	}
    
	//kConnected合并到当前flag中
	flags |= kConnected;
	//停止连接超时
	[self endConnectTimeout];
	
	#if TARGET_OS_IPHONE
	// The endConnectTimeout method executed above incremented the stateIndex.
    //上面的endConnectTimeout,会导致stateIndex增加，所以需要重新赋值
	aStateIndex = stateIndex;
	#endif
	
	// Setup read/write streams (as workaround for specific shortcomings in the iOS platform)
	// 
	// Note:
	// There may be configuration options that must be set by the delegate before opening the streams.
    //打开stream之前必须用相关配置设置代理
	// The primary example is the kCFStreamNetworkServiceTypeVoIP flag, which only works on an unopened stream.
    //主要的例子是kCFStreamNetworkServiceTypeVoIP标记，只能工作在未打开的stream中？
	// 
	// Thus we wait until after the socket:didConnectToHost:port: delegate method has completed.
    //所以我们要等待，连接完成的代理调用完
	// This gives the delegate time to properly configure the streams if needed.
	//这些给了代理时间，去正确的配置Stream，如果是必要的话
    
    //创建个Block来初始化Stream
	dispatch_block_t SetupStreamsPart1 = ^{
        
        NSLog(@"hello~");
		#if TARGET_OS_IPHONE
		//创建读写stream失败，则关闭并报对应错误
		if (![self createReadAndWriteStream])
		{
			[self closeWithError:[self otherError:@"Error creating CFStreams"]];
			return;
		}
		
        //参数是给NO的，就是有可读bytes的时候，不会调用回调函数
		if (![self registerForStreamCallbacksIncludingReadWrite:NO])
		{
			[self closeWithError:[self otherError:@"Error in CFStreamSetClient"]];
			return;
		}
		
		#endif
	};
    //part2设置stream
	dispatch_block_t SetupStreamsPart2 = ^{
		#if TARGET_OS_IPHONE
        //状态不一样直接返回
		if (aStateIndex != stateIndex)
		{
			// The socket has been disconnected.
			return;
		}
		//如果加到runloop上失败
		if (![self addStreamsToRunLoop])
		{
            //错误返回
			[self closeWithError:[self otherError:@"Error in CFStreamScheduleWithRunLoop"]];
			return;
		}
		
        //读写stream open
		if (![self openStreams])
		{
            //开启错误返回
			[self closeWithError:[self otherError:@"Error creating CFStreams"]];
			return;
		}
		
		#endif
	};
	
	// Notify delegate
    //通知代理
	//拿到server端的host port
	NSString *host = [self connectedHost];
	uint16_t port = [self connectedPort];
    //拿到unix域的 url
	NSURL *url = [self connectedUrl];
	//拿到代理
	__strong id theDelegate = delegate;
    
    //代理队列 和 Host不为nil 且响应didConnectToHost代理方法
	if (delegateQueue && host != nil && [theDelegate respondsToSelector:@selector(socket:didConnectToHost:port:)])
	{
        //调用初始化stream1
		SetupStreamsPart1();
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
            //到代理队列调用连接成功的代理方法
			[theDelegate socket:self didConnectToHost:host port:port];
			
            //然后回到socketQueue中去执行初始化stream2
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				SetupStreamsPart2();
			}});
		}});
	}
    //这个是unix domain 请求回调
	else if (delegateQueue && url != nil && [theDelegate respondsToSelector:@selector(socket:didConnectToUrl:)])
	{
		SetupStreamsPart1();
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			[theDelegate socket:self didConnectToUrl:url];
			
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				SetupStreamsPart2();
			}});
		}});
	}
    //否则只初始化stream
	else
	{
		SetupStreamsPart1();
		SetupStreamsPart2();
	}
		
	// Get the connected socket
	
	int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
	
    //fcntl,功能描述：根据文件描述词来操作文件的特性。http://blog.csdn.net/pbymw8iwm/article/details/7974789
	// Enable non-blocking IO on the socket
	//使socket支持非阻塞IO
	int result = fcntl(socketFD, F_SETFL, O_NONBLOCK);
	if (result == -1)
	{
        //失败 ，报错
		NSString *errMsg = @"Error enabling non-blocking IO on socket (fcntl)";
		[self closeWithError:[self otherError:errMsg]];
		
		return;
	}
	
	// Setup our read/write sources
	//初始化读写source
	[self setupReadAndWriteSourcesForNewlyConnectedSocket:socketFD];
	
	// Dequeue any pending read/write requests
	//开始下一个任务
	[self maybeDequeueRead];
	[self maybeDequeueWrite];
}

- (void)didNotConnect:(int)aStateIndex error:(NSError *)error
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring didNotConnect, already disconnected");
		
		// The connect operation has been cancelled.
		// That is, socket was disconnected, or connection has already timed out.
		return;
	}
	
	[self closeWithError:error];
}

//开始连接超时
- (void)startConnectTimeout:(NSTimeInterval)timeout
{
    //只有大于0才执行
	if (timeout >= 0.0)
	{
        //gcd Timer socketQueue中回调
		connectTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
		
		__weak GCDAsyncSocket *weakSelf = self;
		
		dispatch_source_set_event_handler(connectTimer, ^{ @autoreleasepool {
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
			__strong GCDAsyncSocket *strongSelf = weakSelf;
			if (strongSelf == nil) return_from_block;
			//连接超时的操作，取消socket，错误返回等等
			[strongSelf doConnectTimeout];
			
		#pragma clang diagnostic pop
		}});
		
		#if !OS_OBJECT_USE_OBJC
        //iOS6 要cancel中dispatch_release
		dispatch_source_t theConnectTimer = connectTimer;
		dispatch_source_set_cancel_handler(connectTimer, ^{
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			LogVerbose(@"dispatch_release(connectTimer)");
			dispatch_release(theConnectTimer);
			
		#pragma clang diagnostic pop
		});
		#endif
		
        //设置时间 为timeout秒
		dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
        //设置给timer
		dispatch_source_set_timer(connectTimer, tt, DISPATCH_TIME_FOREVER, 0);
		//开启定时器
		dispatch_resume(connectTimer);
	}
}

//关闭连接超时
- (void)endConnectTimeout
{
	LogTrace();
	
    
	if (connectTimer)
	{
        //取消置空
		dispatch_source_cancel(connectTimer);
		connectTimer = NULL;
	}
	
	// Increment stateIndex.
	// This will prevent us from processing results from any related background asynchronous operations.
	// 
	// Note: This should be called from close method even if connectTimer is NULL.
	// This is because one might disconnect a socket prior to a successful connection which had no timeout.
	
    //状态+1
	stateIndex++;
	
    //置空IPV4 IPV6本地信息
	if (connectInterface4)
	{
		connectInterface4 = nil;
	}
	if (connectInterface6)
	{
		connectInterface6 = nil;
	}
}
//连接已超时
- (void)doConnectTimeout
{
	LogTrace();
	
    //关闭连接超时
	[self endConnectTimeout];
    //用错误关闭
	[self closeWithError:[self connectTimeoutError]];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Disconnecting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//错误关闭Socket
- (void)closeWithError:(NSError *)error
{
	LogTrace();
    //先判断当前queue是不是IsOnSocketQueueOrTargetQueueKey
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
    //关闭连接超时
	[self endConnectTimeout];
	
	if (currentRead != nil)  [self endCurrentRead];
	if (currentWrite != nil) [self endCurrentWrite];
	
	[readQueue removeAllObjects];
	[writeQueue removeAllObjects];
	
	[preBuffer reset];
	
	#if TARGET_OS_IPHONE
	{
		if (readStream || writeStream)
		{
			[self removeStreamsFromRunLoop];
			
			if (readStream)
			{
				CFReadStreamSetClient(readStream, kCFStreamEventNone, NULL, NULL);
				CFReadStreamClose(readStream);
				CFRelease(readStream);
				readStream = NULL;
			}
			if (writeStream)
			{
				CFWriteStreamSetClient(writeStream, kCFStreamEventNone, NULL, NULL);
				CFWriteStreamClose(writeStream);
				CFRelease(writeStream);
				writeStream = NULL;
			}
		}
	}
	#endif
	
	[sslPreBuffer reset];
	sslErrCode = lastSSLHandshakeError = noErr;
	
	if (sslContext)
	{
		// Getting a linker error here about the SSLx() functions?
		// You need to add the Security Framework to your application.
		//关闭sslContext
		SSLClose(sslContext);
		
		#if TARGET_OS_IPHONE || (__MAC_OS_X_VERSION_MIN_REQUIRED >= 1080)
		CFRelease(sslContext);
		#else
		SSLDisposeContext(sslContext);
		#endif
		
		sslContext = NULL;
	}
	
	// For some crazy reason (in my opinion), cancelling a dispatch source doesn't
	// invoke the cancel handler if the dispatch source is paused.
	// So we have to unpause the source if needed.
	// This allows the cancel handler to be run, which in turn releases the source and closes the socket.
	
    //如果这些source都为空，直接只关闭socket就可以
	if (!accept4Source && !accept6Source && !acceptUNSource && !readSource && !writeSource)
	{
		LogVerbose(@"manually closing close");

		if (socket4FD != SOCKET_NULL)
		{
			LogVerbose(@"close(socket4FD)");
			close(socket4FD);
			socket4FD = SOCKET_NULL;
		}

		if (socket6FD != SOCKET_NULL)
		{
			LogVerbose(@"close(socket6FD)");
			close(socket6FD);
			socket6FD = SOCKET_NULL;
		}
		
		if (socketUN != SOCKET_NULL)
		{
			LogVerbose(@"close(socketUN)");
			close(socketUN);
			socketUN = SOCKET_NULL;
            //断开Unix domin socket
			unlink(socketUrl.path.fileSystemRepresentation);
			socketUrl = nil;
		}
	}
	else
	{
        //都去取消souce先
		if (accept4Source)
		{
			LogVerbose(@"dispatch_source_cancel(accept4Source)");
			dispatch_source_cancel(accept4Source);
			
			// We never suspend accept4Source
			
			accept4Source = NULL;
		}
		
		if (accept6Source)
		{
			LogVerbose(@"dispatch_source_cancel(accept6Source)");
			dispatch_source_cancel(accept6Source);
			
			// We never suspend accept6Source
			
			accept6Source = NULL;
		}
		
		if (acceptUNSource)
		{
			LogVerbose(@"dispatch_source_cancel(acceptUNSource)");
			dispatch_source_cancel(acceptUNSource);
			
			// We never suspend acceptUNSource
			
			acceptUNSource = NULL;
		}
	
        //读写source需要resume,否则如果是suspend状态的话，cancel不会被调用
		if (readSource)
		{
			LogVerbose(@"dispatch_source_cancel(readSource)");
			dispatch_source_cancel(readSource);
			
			[self resumeReadSource];
			
			readSource = NULL;
		}
		
		if (writeSource)
		{
			LogVerbose(@"dispatch_source_cancel(writeSource)");
			dispatch_source_cancel(writeSource);
			
			[self resumeWriteSource];
			
			writeSource = NULL;
		}
		
		// The sockets will be closed by the cancel handlers of the corresponding source
		socket4FD = SOCKET_NULL;
		socket6FD = SOCKET_NULL;
		socketUN = SOCKET_NULL;
	}
	
	// If the client has passed the connect/accept method, then the connection has at least begun.
	// Notify delegate that it is now ending.
    //判断是否sokcet开启
	BOOL shouldCallDelegate = (flags & kSocketStarted) ? YES : NO;
	BOOL isDeallocating = (flags & kDealloc) ? YES : NO;
	
	// Clear stored socket info and all flags (config remains as is)
    //清楚socket的相关信息，和所有标记
	socketFDBytesAvailable = 0;
	flags = 0;
	sslWriteCachedLength = 0;
	
	if (shouldCallDelegate)
	{
		__strong id theDelegate = delegate;
        //判断是否需要传自己过去，如果已经被销毁，就传nil
		__strong id theSelf = isDeallocating ? nil : self;
		
        //调用断开连接的代理
		if (delegateQueue && [theDelegate respondsToSelector: @selector(socketDidDisconnect:withError:)])
		{
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
				
				[theDelegate socketDidDisconnect:theSelf withError:error];
			}});
		}	
	}
}

//主动断开连接
- (void)disconnect
{
	dispatch_block_t block = ^{ @autoreleasepool {
		
		if (flags & kSocketStarted)
		{
			[self closeWithError:nil];
		}
	}};
	
	// Synchronous disconnection, as documented in the header file
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
}

- (void)disconnectAfterReading
{
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		if (flags & kSocketStarted)
		{
			flags |= (kForbidReadsWrites | kDisconnectAfterReads);
			[self maybeClose];
		}
	}});
}

- (void)disconnectAfterWriting
{
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		if (flags & kSocketStarted)
		{
			flags |= (kForbidReadsWrites | kDisconnectAfterWrites);
			[self maybeClose];
		}
	}});
}

- (void)disconnectAfterReadingAndWriting
{
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		if (flags & kSocketStarted)
		{
			flags |= (kForbidReadsWrites | kDisconnectAfterReads | kDisconnectAfterWrites);
			[self maybeClose];
		}
	}});
}

/**
 * Closes the socket if possible.
 * That is, if all writes have completed, and we're set to disconnect after writing,
 * or if all reads have completed, and we're set to disconnect after reading.
**/
- (void)maybeClose
{
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	BOOL shouldClose = NO;
	
	if (flags & kDisconnectAfterReads)
	{
		if (([readQueue count] == 0) && (currentRead == nil))
		{
			if (flags & kDisconnectAfterWrites)
			{
				if (([writeQueue count] == 0) && (currentWrite == nil))
				{
					shouldClose = YES;
				}
			}
			else
			{
				shouldClose = YES;
			}
		}
	}
	else if (flags & kDisconnectAfterWrites)
	{
		if (([writeQueue count] == 0) && (currentWrite == nil))
		{
			shouldClose = YES;
		}
	}
	
	if (shouldClose)
	{
		[self closeWithError:nil];
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Errors
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (NSError *)badConfigError:(NSString *)errMsg
{
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketBadConfigError userInfo:userInfo];
}

//用该字符串生成一个错误，错误的域名，错误的参数
- (NSError *)badParamError:(NSString *)errMsg
{
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketBadParamError userInfo:userInfo];
}


+ (NSError *)gaiError:(int)gai_error
{
    //getaddrinfo出错时返回非零值，gai_strerror根据返回的非零值返回指向对应的出错信息字符串的指针
    //EAI_ADDRFAMILY	不支持hostname的地址族
//    EAI_AGAIN	名字解析中的暂时失败
//    EAI_BADFLAGS	ai_flags的值无效
//    EAI_FAIL	名字解析中不可恢复的失败
//    EAI_FAMILY	不支持ai_family
//    EAI_MEMORY	内存分配失败
//    EAI_NODATA	没有与hostname相关联的地址
//    EAI_NONAME	hostname或service未提供，或者不可知
//    EAI_SERVICE	不支持ai_socktype类型的service
//    EAI_SOCKTYPE	不支持ai_socktype
//    EAI_SYSTEM	errno中有系统错误返回
    
	NSString *errMsg = [NSString stringWithCString:gai_strerror(gai_error) encoding:NSASCIIStringEncoding];
    //根据错误内容生成字典
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	//返回该错误，code为gai_error
	return [NSError errorWithDomain:@"kCFStreamErrorDomainNetDB" code:gai_error userInfo:userInfo];
}

//根据字符串返回错误 NSError *
- (NSError *)errnoErrorWithReason:(NSString *)reason
{
    //errno记录系统的最后一次错误代码。代码是一个int型的值，在errno.h中定义，strerror，code转Str
	NSString *errMsg = [NSString stringWithUTF8String:strerror(errno)];
	NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:errMsg, NSLocalizedDescriptionKey,
	                                                                    reason, NSLocalizedFailureReasonErrorKey, nil];
	
	return [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:userInfo];
}

- (NSError *)errnoError
{
	NSString *errMsg = [NSString stringWithUTF8String:strerror(errno)];
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:userInfo];
}

//得到SSL数据错误
- (NSError *)sslError:(OSStatus)ssl_error
{
	NSString *msg = @"Error code definition can be found in Apple's SecureTransport.h";
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:msg forKey:NSLocalizedRecoverySuggestionErrorKey];
	
	return [NSError errorWithDomain:@"kCFStreamErrorDomainSSL" code:ssl_error userInfo:userInfo];
}

//生成连接超时的错误
- (NSError *)connectTimeoutError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketConnectTimeoutError",
	                                                     @"GCDAsyncSocket", [NSBundle mainBundle],
	                                                     @"Attempt to connect to host timed out", nil);
	
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketConnectTimeoutError userInfo:userInfo];
}

/**
 * Returns a standard AsyncSocket maxed out error.
**/
//数据溢出错误
- (NSError *)readMaxedOutError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketReadMaxedOutError",
														 @"GCDAsyncSocket", [NSBundle mainBundle],
														 @"Read operation reached set maximum length", nil);
	
	NSDictionary *info = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketReadMaxedOutError userInfo:info];
}

/**
 * Returns a standard AsyncSocket write timeout error.
**/
- (NSError *)readTimeoutError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketReadTimeoutError",
	                                                     @"GCDAsyncSocket", [NSBundle mainBundle],
	                                                     @"Read operation timed out", nil);
	
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketReadTimeoutError userInfo:userInfo];
}

/**
 * Returns a standard AsyncSocket write timeout error.
**/
- (NSError *)writeTimeoutError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketWriteTimeoutError",
	                                                     @"GCDAsyncSocket", [NSBundle mainBundle],
	                                                     @"Write operation timed out", nil);
	
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketWriteTimeoutError userInfo:userInfo];
}

- (NSError *)connectionClosedError
{
	NSString *errMsg = NSLocalizedStringWithDefaultValue(@"GCDAsyncSocketClosedError",
	                                                     @"GCDAsyncSocket", [NSBundle mainBundle],
	                                                     @"Socket closed by remote peer", nil);
	
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketClosedError userInfo:userInfo];
}

- (NSError *)otherError:(NSString *)errMsg
{
	NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errMsg forKey:NSLocalizedDescriptionKey];
	
	return [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncSocketOtherError userInfo:userInfo];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Diagnostics
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//判断当前是不是断开连接
- (BOOL)isDisconnected
{
	__block BOOL result = NO;
	
	dispatch_block_t block = ^{
        //用 flags 与 kSocketStarted 位与运算 ，非0为真 说明开始了， 则NO，否则为YES
		result = (flags & kSocketStarted) ? NO : YES;
	};
	
    //这些操作都是这么做
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
        //阻塞队列，阻塞线程的方式去做
		dispatch_sync(socketQueue, block);
	
	return result;
}

//判断是不是连接
- (BOOL)isConnected
{
	__block BOOL result = NO;
	
	dispatch_block_t block = ^{
		result = (flags & kConnected) ? YES : NO;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

//拿到连接的Host
- (NSString *)connectedHost
{
    //判断是否在当前socket队列
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socket4FD != SOCKET_NULL)
            
			return [self connectedHostFromSocket4:socket4FD];
		if (socket6FD != SOCKET_NULL)
			return [self connectedHostFromSocket6:socket6FD];
		
		return nil;
	}
	else
	{
		__block NSString *result = nil;
		
		dispatch_sync(socketQueue, ^{ @autoreleasepool {
			
			if (socket4FD != SOCKET_NULL)
				result = [self connectedHostFromSocket4:socket4FD];
			else if (socket6FD != SOCKET_NULL)
				result = [self connectedHostFromSocket6:socket6FD];
		}});
		
		return result;
	}
}

//拿到连接的Port
- (uint16_t)connectedPort
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socket4FD != SOCKET_NULL)
			return [self connectedPortFromSocket4:socket4FD];
		if (socket6FD != SOCKET_NULL)
			return [self connectedPortFromSocket6:socket6FD];
		
		return 0;
	}
	else
	{
		__block uint16_t result = 0;
		
		dispatch_sync(socketQueue, ^{
			// No need for autorelease pool
			
			if (socket4FD != SOCKET_NULL)
				result = [self connectedPortFromSocket4:socket4FD];
			else if (socket6FD != SOCKET_NULL)
				result = [self connectedPortFromSocket6:socket6FD];
		});
		
		return result;
	}
}

- (NSURL *)connectedUrl
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socketUN != SOCKET_NULL)
			return [self connectedUrlFromSocketUN:socketUN];
		
		return nil;
	}
	else
	{
		__block NSURL *result = nil;
		
		dispatch_sync(socketQueue, ^{ @autoreleasepool {
			
			if (socketUN != SOCKET_NULL)
				result = [self connectedUrlFromSocketUN:socketUN];
		}});
		
		return result;
	}
}

- (NSString *)localHost
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socket4FD != SOCKET_NULL)
			return [self localHostFromSocket4:socket4FD];
		if (socket6FD != SOCKET_NULL)
			return [self localHostFromSocket6:socket6FD];
		
		return nil;
	}
	else
	{
		__block NSString *result = nil;
		
		dispatch_sync(socketQueue, ^{ @autoreleasepool {
			
			if (socket4FD != SOCKET_NULL)
				result = [self localHostFromSocket4:socket4FD];
			else if (socket6FD != SOCKET_NULL)
				result = [self localHostFromSocket6:socket6FD];
		}});
		
		return result;
	}
}

- (uint16_t)localPort
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		if (socket4FD != SOCKET_NULL)
			return [self localPortFromSocket4:socket4FD];
		if (socket6FD != SOCKET_NULL)
			return [self localPortFromSocket6:socket6FD];
		
		return 0;
	}
	else
	{
		__block uint16_t result = 0;
		
		dispatch_sync(socketQueue, ^{
			// No need for autorelease pool
			
			if (socket4FD != SOCKET_NULL)
				result = [self localPortFromSocket4:socket4FD];
			else if (socket6FD != SOCKET_NULL)
				result = [self localPortFromSocket6:socket6FD];
		});
		
		return result;
	}
}

- (NSString *)connectedHost4
{
	if (socket4FD != SOCKET_NULL)
		return [self connectedHostFromSocket4:socket4FD];
	
	return nil;
}

- (NSString *)connectedHost6
{
	if (socket6FD != SOCKET_NULL)
		return [self connectedHostFromSocket6:socket6FD];
	
	return nil;
}

- (uint16_t)connectedPort4
{
	if (socket4FD != SOCKET_NULL)
		return [self connectedPortFromSocket4:socket4FD];
	
	return 0;
}

- (uint16_t)connectedPort6
{
	if (socket6FD != SOCKET_NULL)
		return [self connectedPortFromSocket6:socket6FD];
	
	return 0;
}

- (NSString *)localHost4
{
	if (socket4FD != SOCKET_NULL)
		return [self localHostFromSocket4:socket4FD];
	
	return nil;
}

- (NSString *)localHost6
{
	if (socket6FD != SOCKET_NULL)
		return [self localHostFromSocket6:socket6FD];
	
	return nil;
}

//本地IPV4 Port
- (uint16_t)localPort4
{
	if (socket4FD != SOCKET_NULL)
		return [self localPortFromSocket4:socket4FD];
	
	return 0;
}

- (uint16_t)localPort6
{
	if (socket6FD != SOCKET_NULL)
		return [self localPortFromSocket6:socket6FD];
	
	return 0;
}

//通过地址拿到host IPV4
- (NSString *)connectedHostFromSocket4:(int)socketFD
{
	struct sockaddr_in sockaddr4;
	socklen_t sockaddr4len = sizeof(sockaddr4);
	//这个函数用来获取socket的对方地址，只有连接成功才能调用这个函数，否则是获取不到正确的值
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
	{
		return nil;
	}
    //用server的地址去获取Host
	return [[self class] hostFromSockaddr4:&sockaddr4];
}
//通过地址拿到host IPV6
- (NSString *)connectedHostFromSocket6:(int)socketFD
{
	struct sockaddr_in6 sockaddr6;
	socklen_t sockaddr6len = sizeof(sockaddr6);
	
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
	{
		return nil;
	}
	return [[self class] hostFromSockaddr6:&sockaddr6];
}

- (uint16_t)connectedPortFromSocket4:(int)socketFD
{
	struct sockaddr_in sockaddr4;
	socklen_t sockaddr4len = sizeof(sockaddr4);
	
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
	{
		return 0;
	}
	return [[self class] portFromSockaddr4:&sockaddr4];
}

- (uint16_t)connectedPortFromSocket6:(int)socketFD
{
	struct sockaddr_in6 sockaddr6;
	socklen_t sockaddr6len = sizeof(sockaddr6);
	
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
	{
		return 0;
	}
	return [[self class] portFromSockaddr6:&sockaddr6];
}

//获取到连接的Url
- (NSURL *)connectedUrlFromSocketUN:(int)socketFD
{
	struct sockaddr_un sockaddr;
	socklen_t sockaddrlen = sizeof(sockaddr);
	//还是用该函数拿到到server端的地址
	if (getpeername(socketFD, (struct sockaddr *)&sockaddr, &sockaddrlen) < 0)
	{
		return 0;
	}
	return [[self class] urlFromSockaddrUN:&sockaddr];
}

//拿到本地IPV4 Host
- (NSString *)localHostFromSocket4:(int)socketFD
{
	struct sockaddr_in sockaddr4;
	socklen_t sockaddr4len = sizeof(sockaddr4);
	
	if (getsockname(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
	{
		return nil;
	}
	return [[self class] hostFromSockaddr4:&sockaddr4];
}

//拿到本地IPV6 Host
- (NSString *)localHostFromSocket6:(int)socketFD
{
	struct sockaddr_in6 sockaddr6;
	socklen_t sockaddr6len = sizeof(sockaddr6);
	
	if (getsockname(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
	{
		return nil;
	}
	return [[self class] hostFromSockaddr6:&sockaddr6];
}

//得到本地IPV4端口
- (uint16_t)localPortFromSocket4:(int)socketFD
{
	struct sockaddr_in sockaddr4;
	socklen_t sockaddr4len = sizeof(sockaddr4);
	
	if (getsockname(socketFD, (struct sockaddr *)&sockaddr4, &sockaddr4len) < 0)
	{
		return 0;
	}
	return [[self class] portFromSockaddr4:&sockaddr4];
}
//得到本地IPV6端口

- (uint16_t)localPortFromSocket6:(int)socketFD
{
	struct sockaddr_in6 sockaddr6;
	socklen_t sockaddr6len = sizeof(sockaddr6);
	
	if (getsockname(socketFD, (struct sockaddr *)&sockaddr6, &sockaddr6len) < 0)
	{
		return 0;
	}
	return [[self class] portFromSockaddr6:&sockaddr6];
}

- (NSData *)connectedAddress
{
	__block NSData *result = nil;
	
	dispatch_block_t block = ^{
		if (socket4FD != SOCKET_NULL)
		{
			struct sockaddr_in sockaddr4;
			socklen_t sockaddr4len = sizeof(sockaddr4);
			
			if (getpeername(socket4FD, (struct sockaddr *)&sockaddr4, &sockaddr4len) == 0)
			{
				result = [[NSData alloc] initWithBytes:&sockaddr4 length:sockaddr4len];
			}
		}
		
		if (socket6FD != SOCKET_NULL)
		{
			struct sockaddr_in6 sockaddr6;
			socklen_t sockaddr6len = sizeof(sockaddr6);
			
			if (getpeername(socket6FD, (struct sockaddr *)&sockaddr6, &sockaddr6len) == 0)
			{
				result = [[NSData alloc] initWithBytes:&sockaddr6 length:sockaddr6len];
			}
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

- (NSData *)localAddress
{
	__block NSData *result = nil;
	
	dispatch_block_t block = ^{
		if (socket4FD != SOCKET_NULL)
		{
			struct sockaddr_in sockaddr4;
			socklen_t sockaddr4len = sizeof(sockaddr4);
			
			if (getsockname(socket4FD, (struct sockaddr *)&sockaddr4, &sockaddr4len) == 0)
			{
				result = [[NSData alloc] initWithBytes:&sockaddr4 length:sockaddr4len];
			}
		}
		
		if (socket6FD != SOCKET_NULL)
		{
			struct sockaddr_in6 sockaddr6;
			socklen_t sockaddr6len = sizeof(sockaddr6);
			
			if (getsockname(socket6FD, (struct sockaddr *)&sockaddr6, &sockaddr6len) == 0)
			{
				result = [[NSData alloc] initWithBytes:&sockaddr6 length:sockaddr6len];
			}
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

- (BOOL)isIPv4
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return (socket4FD != SOCKET_NULL);
	}
	else
	{
		__block BOOL result = NO;
		
		dispatch_sync(socketQueue, ^{
			result = (socket4FD != SOCKET_NULL);
		});
		
		return result;
	}
}

- (BOOL)isIPv6
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return (socket6FD != SOCKET_NULL);
	}
	else
	{
		__block BOOL result = NO;
		
		dispatch_sync(socketQueue, ^{
			result = (socket6FD != SOCKET_NULL);
		});
		
		return result;
	}
}

- (BOOL)isSecure
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return (flags & kSocketSecure) ? YES : NO;
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = (flags & kSocketSecure) ? YES : NO;
		});
		
		return result;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Utilities
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Finds the address of an interface description.
 * An inteface description may be an interface name (en0, en1, lo0) or corresponding IP (192.168.4.34).
 * 
 * The interface description may optionally contain a port number at the end, separated by a colon.
 //可能在结尾包含一个：端口号
 * If a non-zero port parameter is provided, any port number in the interface description is ignored.
 //如果有非0的Port参数提供，那么之前的任何：端口号都会被忽略
 * 
 * The returned value is a 'struct sockaddr' wrapped in an NSMutableData object.
 //返回的value是地址型的结构体，包在一个NSMutableData对象中
**/
//根据interface 得到IPV4 IPV6地址
- (void)getInterfaceAddress4:(NSMutableData **)interfaceAddr4Ptr
                    address6:(NSMutableData **)interfaceAddr6Ptr
             fromDescription:(NSString *)interfaceDescription
                        port:(uint16_t)port
{
	NSMutableData *addr4 = nil;
	NSMutableData *addr6 = nil;
	
	NSString *interface = nil;
	
    //先用:分割
	NSArray *components = [interfaceDescription componentsSeparatedByString:@":"];
	if ([components count] > 0)
	{
		NSString *temp = [components objectAtIndex:0];
		if ([temp length] > 0)
		{
			interface = temp;
		}
	}
	if ([components count] > 1 && port == 0)
	{
        //拿到port strtol函数，将一个字符串，根据base参数转成长整型，如base值为10则采用10进制，若base值为16则采用16进制
		long portL = strtol([[components objectAtIndex:1] UTF8String], NULL, 10);
		//UINT16_MAX,65535最大端口号
		if (portL > 0 && portL <= UINT16_MAX)
		{
			port = (uint16_t)portL;
		}
	}
	
    //为空则自己创建一个 0x00000000 ，全是0 ，为线路地址
    //如果端口为0 通常用于分析操作系统。这一方法能够工作是因为在一些系统中“0”是无效端口，当你试图使用通常的闭合端口连接它时将产生不同的结果。一种典型的扫描，使用IP地址为0.0.0.0，设置ACK位并在以太网层广播。
	if (interface == nil)
	{
		// ANY address
		//生成一个地址结构体     sockaddr_in类型
        /*
         struct sockaddr_in {
         __uint8_t	sin_len;
         sa_family_t	sin_family;
         in_port_t	sin_port;
         //真正存ip地址的，2个字节 16位
         struct	in_addr sin_addr;
         char		sin_zero[8];
         };

         */
		struct sockaddr_in sockaddr4;
        
        //memset作用是在一段内存块中填充某个给定的值，它是对较大的结构体或数组进行清零操作的一种最快方法
        
        //memset(void *s,int ch,size_t n);函数，第一个参数为指针地址，第二个为设置值，第三个为连续设置的长度（大小）
		memset(&sockaddr4, 0, sizeof(sockaddr4));
		//结构体长度
		sockaddr4.sin_len         = sizeof(sockaddr4);
        //addressFamily IPv4(AF_INET) 或 IPv6(AF_INET6)。
		sockaddr4.sin_family      = AF_INET;
        //端口号 htons将主机字节顺序转换成网络字节顺序  16位
		sockaddr4.sin_port        = htons(port);
        //htonl ,将INADDR_ANY：0.0.0.0,不确定地址，或者任意地址  htonl 32位。 也是转为网络字节序
      
        //ipv4 32位  4个字节    INADDR_ANY，0x00000000 （16进制，一个0代表4位，8个0就是32位） =   4个字节的
		sockaddr4.sin_addr.s_addr = htonl(INADDR_ANY);
		
        //一样
        //        struct sockaddr_in6 {
        //            __uint8_t	sin6_len;	/* length of this struct(sa_family_t) */
        //            sa_family_t	sin6_family;	/* AF_INET6 (sa_family_t) */
        //            in_port_t	sin6_port;	/* Transport layer port # (in_port_t) */
        //            __uint32_t	sin6_flowinfo;	/* IP6 flow information */
        //            //真正存ip地址的，16个字节 128位
        //            struct in6_addr	sin6_addr;	/* IP6 address */
        //            __uint32_t	sin6_scope_id;	/* scope zone index */
        //        };
        
        
		struct sockaddr_in6 sockaddr6;
		memset(&sockaddr6, 0, sizeof(sockaddr6));
		
		sockaddr6.sin6_len       = sizeof(sockaddr6);
        //ipv6
		sockaddr6.sin6_family    = AF_INET6;
        //port
		sockaddr6.sin6_port      = htons(port);
        //任意ipv6的地址
        
        //        struct in6_addr {
        //为共用体，所以同一时间，只可能有一个有值
        //            union {
        //                __uint8_t   __u6_addr8[16];   //16字节
        //                __uint16_t  __u6_addr16[8];    //16字节
        //                __uint32_t  __u6_addr32[4];   //16字节
        //            } __u6_addr;			/* 128-bit IP6 address */
        
        //        };
        //共128位
        sockaddr6.sin6_addr      = in6addr_any;
		
        //把这两个结构体转成data
		addr4 = [NSMutableData dataWithBytes:&sockaddr4 length:sizeof(sockaddr4)];
		addr6 = [NSMutableData dataWithBytes:&sockaddr6 length:sizeof(sockaddr6)];
	}
    //如果localhost、loopback 回环地址，虚拟地址，路由器工作它就存在。一般用来标识路由器
    //这两种的话就赋值为127.0.0.1，端口为port
	else if ([interface isEqualToString:@"localhost"] || [interface isEqualToString:@"  "])
	{
		// LOOPBACK address
        
        //ipv4
		struct sockaddr_in sockaddr4;
		memset(&sockaddr4, 0, sizeof(sockaddr4));
		
		sockaddr4.sin_len         = sizeof(sockaddr4);
		sockaddr4.sin_family      = AF_INET;
		sockaddr4.sin_port        = htons(port);
        
        //#define	INADDR_LOOPBACK		(u_int32_t)0x7f000001
        //7f000001->1111111 00000000 00000000 00000001->127.0.0.1
		sockaddr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		
        //ipv6
		struct sockaddr_in6 sockaddr6;
		memset(&sockaddr6, 0, sizeof(sockaddr6));
		
		sockaddr6.sin6_len       = sizeof(sockaddr6);
		sockaddr6.sin6_family    = AF_INET6;
		sockaddr6.sin6_port      = htons(port);
        //和之前一样
        //struct in6_addr {
//        union {
//            __uint8_t   __u6_addr8[16];
//            __uint16_t  __u6_addr16[8];
//            __uint32_t  __u6_addr32[4];
//        } __u6_addr;			/* 128-bit IP6 address */
//        };
		sockaddr6.sin6_addr      = in6addr_loopback;
		//赋值
		addr4 = [NSMutableData dataWithBytes:&sockaddr4 length:sizeof(sockaddr4)];
		addr6 = [NSMutableData dataWithBytes:&sockaddr6 length:sizeof(sockaddr6)];
	}
    //非localhost、loopback，去获取本机IP，看和传进来Interface是同名或者同IP，相同才给赋端口号，把数据封装进Data。否则为nil
	else
	{
        //转成cString
		const char *iface = [interface UTF8String];
		
        /*
         struct ifaddrs {
         //指向链表的下一个成员
         struct ifaddrs  *ifa_next;
         //接口名称
         char		*ifa_name;
         //接口标识位（比如当IFF_BROADCAST或IFF_POINTOPOINT设置到此标识位时，影响联合体变量ifu_broadaddr存储广播地址或ifu_dstaddr记录点对点地址）； ？
         unsigned int	 ifa_flags;
         //接口地址
         struct sockaddr	*ifa_addr;
         //存储该接口的子网掩码；
         struct sockaddr	*ifa_netmask;
        
         //点对点的地址？？类似全0？
         struct sockaddr	*ifa_dstaddr;
         //ifa_data存储了该接口协议族的特殊信息，它通常是NULL（一般不关注他）。
         void		*ifa_data;
         };
         */
       
        //定义结构体指针，这个指针是本地IP
		struct ifaddrs *addrs;
		const struct ifaddrs *cursor;
		
        //获取到本机IP，为0说明成功了
		if ((getifaddrs(&addrs) == 0))
		{
            //赋值
			cursor = addrs;
            //如果IP不为空，则循环链表去设置
			while (cursor != NULL)
			{
                //如果 addr4 IPV4地址为空，而且地址类型为IPV4
				if ((addr4 == nil) && (cursor->ifa_addr->sa_family == AF_INET))
				{
					// IPv4
					
					struct sockaddr_in nativeAddr4;
                    //memcpy内存copy函数，把src开始到size的字节数copy到 dest中
					memcpy(&nativeAddr4, cursor->ifa_addr, sizeof(nativeAddr4));
					
                    //比较两个字符串是否相同，本机的IP名，和接口interface是否相同
					if (strcmp(cursor->ifa_name, iface) == 0)
					{
						// Name match
						//相同则赋值 port
						nativeAddr4.sin_port = htons(port);
						//用data封号IPV4地址
						addr4 = [NSMutableData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
					}
                    //本机IP名和interface不相同
					else
					{
                        //声明一个IP 16位的数组
						char ip[INET_ADDRSTRLEN];
                        
						//inet_pton和inet_ntop这2个IP地址转换函数，可以在将IP地址在“点分十进制”和“二进制整数”之间转换
                        
                        //多了一个参数socklen_t cnt,他是所指向缓存区dst的大小，避免溢出，如果缓存区太小无法存储地址的值，则返回一个空指针，并将errno置为ENOSPC
                        //const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);

                        //这里是转成了10进制。。（因为获取到的是二进制IP）
						const char *conversion = inet_ntop(AF_INET, &nativeAddr4.sin_addr, ip, sizeof(ip));
                        
                        //如果conversion不为空，说明转换成功而且 ，比较转换后的IP，和interface是否相同
						if ((conversion != NULL) && (strcmp(ip, iface) == 0))
						{
							// IP match
                            //相同则赋值 port
							nativeAddr4.sin_port = htons(port);
							
							addr4 = [NSMutableData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
						}
					}
				}
                //IPV6 一样
				else if ((addr6 == nil) && (cursor->ifa_addr->sa_family == AF_INET6))
				{
					// IPv6
					
					struct sockaddr_in6 nativeAddr6;
					memcpy(&nativeAddr6, cursor->ifa_addr, sizeof(nativeAddr6));
					
					if (strcmp(cursor->ifa_name, iface) == 0)
					{
						// Name match
						
						nativeAddr6.sin6_port = htons(port);
						
						addr6 = [NSMutableData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
					}
					else
					{
						char ip[INET6_ADDRSTRLEN];
						
						const char *conversion = inet_ntop(AF_INET6, &nativeAddr6.sin6_addr, ip, sizeof(ip));
						
						if ((conversion != NULL) && (strcmp(ip, iface) == 0))
						{
							// IP match
							
							nativeAddr6.sin6_port = htons(port);
							
							addr6 = [NSMutableData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
						}
					}
				}
				
                //指向链表下一个addr
				cursor = cursor->ifa_next;
			}
			//和getifaddrs对应，释放这部分内存
			freeifaddrs(addrs);
		}
	}
	//如果这两个二级指针存在，则取成一级指针，把addr4赋值给它
	if (interfaceAddr4Ptr) *interfaceAddr4Ptr = addr4;
	if (interfaceAddr6Ptr) *interfaceAddr6Ptr = addr6;
}

//根据Url拿到地址结构体
- (NSData *)getInterfaceAddressFromUrl:(NSURL *)url;
{
    //拿到url字符串
	NSString *path = url.path;
	if (path.length == 0) {
		return nil;
	}
	//uinix domin socket地址结构体
//    struct	sockaddr_un {
//        unsigned char	sun_len;	/* sockaddr len including null */
//        sa_family_t	sun_family;	/* [XSI] AF_UNIX */
//        char		sun_path[104];	/* [XSI] path name (gag) */
//    };
    
    struct sockaddr_un nativeAddr;
    //设置为AF_UNIX unix domin
    nativeAddr.sun_family = AF_UNIX;
    
    //strlcpy(char *__dst, const char *__source, size_t __size);
    //赋值文件地址到结构体中
    strlcpy(nativeAddr.sun_path, path.fileSystemRepresentation, sizeof(nativeAddr.sun_path));
    nativeAddr.sun_len = SUN_LEN(&nativeAddr);
    //包裹成data
    NSData *interface = [NSData dataWithBytes:&nativeAddr length:sizeof(struct sockaddr_un)];
	
	return interface;
}

//初始化读写source
- (void)setupReadAndWriteSourcesForNewlyConnectedSocket:(int)socketFD
{
    //GCD source DISPATCH_SOURCE_TYPE_READ 会一直监视着 socketFD，直到有数据可读
	readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, socketFD, 0, socketQueue);
    //_dispatch_source_type_write ：监视着 socketFD，监视还有没有可写空间
	writeSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, socketFD, 0, socketQueue);
	
	// Setup event handlers
	
	__weak GCDAsyncSocket *weakSelf = self;
    
#pragma mark readSource的回调

	//GCD事件句柄  读，当socket中有数据流出现，就会触发这个句柄，全自动，不需要手动触发
	dispatch_source_set_event_handler(readSource, ^{ @autoreleasepool {
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		__strong GCDAsyncSocket *strongSelf = weakSelf;
		if (strongSelf == nil) return_from_block;
		
		LogVerbose(@"readEventBlock");
		//从readSource中，获取到数据长度，
		strongSelf->socketFDBytesAvailable = dispatch_source_get_data(strongSelf->readSource);
		LogVerbose(@"socketFDBytesAvailable: %lu", strongSelf->socketFDBytesAvailable);
		
        //如果长度大于0，开始读数据
		if (strongSelf->socketFDBytesAvailable > 0)
			[strongSelf doReadData];
		else
            //因为触发了，但是却没有可读数据，说明读到当前socket缓冲边界了。做边界处理
			[strongSelf doReadEOF];
		
	#pragma clang diagnostic pop
	}});
	
    //写事件句柄
	dispatch_source_set_event_handler(writeSource, ^{ @autoreleasepool {
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		__strong GCDAsyncSocket *strongSelf = weakSelf;
		if (strongSelf == nil) return_from_block;
		
		LogVerbose(@"writeEventBlock");
		//标记为接受数据
		strongSelf->flags |= kSocketCanAcceptBytes;
        //开始写
		[strongSelf doWriteData];
		
	#pragma clang diagnostic pop
	}});
	
	// Setup cancel handlers
	
	__block int socketFDRefCount = 2;
	
	#if !OS_OBJECT_USE_OBJC
	dispatch_source_t theReadSource = readSource;
	dispatch_source_t theWriteSource = writeSource;
	#endif
	
    //读写取消的句柄
	dispatch_source_set_cancel_handler(readSource, ^{
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		LogVerbose(@"readCancelBlock");
		
		#if !OS_OBJECT_USE_OBJC
		LogVerbose(@"dispatch_release(readSource)");
		dispatch_release(theReadSource);
		#endif
		
		if (--socketFDRefCount == 0)
		{
			LogVerbose(@"close(socketFD)");
            //关闭socket
			close(socketFD);
		}
		
	#pragma clang diagnostic pop
	});
	
	dispatch_source_set_cancel_handler(writeSource, ^{
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		
		LogVerbose(@"writeCancelBlock");
		
		#if !OS_OBJECT_USE_OBJC
		LogVerbose(@"dispatch_release(writeSource)");
		dispatch_release(theWriteSource);
		#endif
		
		if (--socketFDRefCount == 0)
		{
			LogVerbose(@"close(socketFD)");
            //关闭socket
			close(socketFD);
		}
		
	#pragma clang diagnostic pop
	});
	
	// We will not be able to read until data arrives.
	// But we should be able to write immediately.
	
    //设置未读数量为0
	socketFDBytesAvailable = 0;
    //把读挂起的状态移除
	flags &= ~kReadSourceSuspended;
	
	LogVerbose(@"dispatch_resume(readSource)");
    //开启读source
	dispatch_resume(readSource);
	
    //标记为当前可接受数据
	flags |= kSocketCanAcceptBytes;
    //先把写source标记为挂起
	flags |= kWriteSourceSuspended;
}
//判断是否用的是 CFStream的TLS
- (BOOL)usingCFStreamForTLS
{
	#if TARGET_OS_IPHONE
	
	if ((flags & kSocketSecure) && (flags & kUsingCFStreamForTLS))
	{
		// The startTLS method was given the GCDAsyncSocketUseCFStreamForTLS flag.
		
		return YES;
	}
	
	#endif
	
	return NO;
}

//是否用安全的传输TLS，不是CTStreamTLS,和上面的刚好相反
- (BOOL)usingSecureTransportForTLS
{
	// Invoking this method is equivalent to ![self usingCFStreamForTLS] (just more readable)
	
	#if TARGET_OS_IPHONE
	
	if ((flags & kSocketSecure) && (flags & kUsingCFStreamForTLS))
	{
		// The startTLS method was given the GCDAsyncSocketUseCFStreamForTLS flag.
		
		return NO;
	}
	
	#endif
	
	return YES;
}

//挂起读的source
- (void)suspendReadSource
{
    //如果当前不是挂起状态，则挂起
	if (!(flags & kReadSourceSuspended))
	{
		LogVerbose(@"dispatch_suspend(readSource)");
		
		dispatch_suspend(readSource);
		flags |= kReadSourceSuspended;
	}
}
//恢复读的source
- (void)resumeReadSource
{
	if (flags & kReadSourceSuspended)
	{
		LogVerbose(@"dispatch_resume(readSource)");
		
		dispatch_resume(readSource);
		flags &= ~kReadSourceSuspended;
	}
}

- (void)suspendWriteSource
{
	if (!(flags & kWriteSourceSuspended))
	{
		LogVerbose(@"dispatch_suspend(writeSource)");
		
		dispatch_suspend(writeSource);
		flags |= kWriteSourceSuspended;
	}
}

- (void)resumeWriteSource
{
	if (flags & kWriteSourceSuspended)
	{
		LogVerbose(@"dispatch_resume(writeSource)");
		
		dispatch_resume(writeSource);
		flags &= ~kWriteSourceSuspended;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Reading
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)readDataWithTimeout:(NSTimeInterval)timeout tag:(long)tag
{
	[self readDataWithTimeout:timeout buffer:nil bufferOffset:0 maxLength:0 tag:tag];
}

- (void)readDataWithTimeout:(NSTimeInterval)timeout
                     buffer:(NSMutableData *)buffer
               bufferOffset:(NSUInteger)offset
                        tag:(long)tag
{
	[self readDataWithTimeout:timeout buffer:buffer bufferOffset:offset maxLength:0 tag:tag];
}

//用偏移量 maxLength 读取数据
- (void)readDataWithTimeout:(NSTimeInterval)timeout
                     buffer:(NSMutableData *)buffer
               bufferOffset:(NSUInteger)offset
                  maxLength:(NSUInteger)length
                        tag:(long)tag
{
	if (offset > [buffer length]) {
		LogWarn(@"Cannot read: offset > [buffer length]");
		return;
	}
	
	GCDAsyncReadPacket *packet = [[GCDAsyncReadPacket alloc] initWithData:buffer
	                                                          startOffset:offset
	                                                            maxLength:length
	                                                              timeout:timeout
	                                                           readLength:0
	                                                           terminator:nil
	                                                                  tag:tag];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		LogTrace();
		
		if ((flags & kSocketStarted) && !(flags & kForbidReadsWrites))
		{
            //往读的队列添加任务，任务是包的形式
			[readQueue addObject:packet];
			[self maybeDequeueRead];
		}
	}});
	
	// Do not rely on the block being run in order to release the packet,
	// as the queue might get released without the block completing.
}

- (void)readDataToLength:(NSUInteger)length withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
	[self readDataToLength:length withTimeout:timeout buffer:nil bufferOffset:0 tag:tag];
}

//用指定长度读取数据
- (void)readDataToLength:(NSUInteger)length
             withTimeout:(NSTimeInterval)timeout
                  buffer:(NSMutableData *)buffer
            bufferOffset:(NSUInteger)offset
                     tag:(long)tag
{
	if (length == 0) {
		LogWarn(@"Cannot read: length == 0");
		return;
	}
	if (offset > [buffer length]) {
		LogWarn(@"Cannot read: offset > [buffer length]");
		return;
	}
	
	GCDAsyncReadPacket *packet = [[GCDAsyncReadPacket alloc] initWithData:buffer
	                                                          startOffset:offset
	                                                            maxLength:0
	                                                              timeout:timeout
	                                                           readLength:length
	                                                           terminator:nil
	                                                                  tag:tag];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		LogTrace();
		
		if ((flags & kSocketStarted) && !(flags & kForbidReadsWrites))
		{
            //往读的队列添加任务，任务是包的形式
			[readQueue addObject:packet];
			[self maybeDequeueRead];
		}
	}});
	
	// Do not rely on the block being run in order to release the packet,
	// as the queue might get released without the block completing.
}

- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
	[self readDataToData:data withTimeout:timeout buffer:nil bufferOffset:0 maxLength:0 tag:tag];
}

- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
                   tag:(long)tag
{
	[self readDataToData:data withTimeout:timeout buffer:buffer bufferOffset:offset maxLength:0 tag:tag];
}

- (void)readDataToData:(NSData *)data withTimeout:(NSTimeInterval)timeout maxLength:(NSUInteger)length tag:(long)tag
{
	[self readDataToData:data withTimeout:timeout buffer:nil bufferOffset:0 maxLength:length tag:tag];
}

//用界限Data去读取数据
- (void)readDataToData:(NSData *)data
           withTimeout:(NSTimeInterval)timeout
                buffer:(NSMutableData *)buffer
          bufferOffset:(NSUInteger)offset
             maxLength:(NSUInteger)maxLength
                   tag:(long)tag
{
	if ([data length] == 0) {
		LogWarn(@"Cannot read: [data length] == 0");
		return;
	}
	if (offset > [buffer length]) {
		LogWarn(@"Cannot read: offset > [buffer length]");
		return;
	}
	if (maxLength > 0 && maxLength < [data length]) {
		LogWarn(@"Cannot read: maxLength > 0 && maxLength < [data length]");
		return;
	}
	
	GCDAsyncReadPacket *packet = [[GCDAsyncReadPacket alloc] initWithData:buffer
	                                                          startOffset:offset
	                                                            maxLength:maxLength
	                                                              timeout:timeout
	                                                           readLength:0
	                                                           terminator:data
	                                                                  tag:tag];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		LogTrace();
		
		if ((flags & kSocketStarted) && !(flags & kForbidReadsWrites))
		{
            //往读的队列添加任务，任务是包的形式
			[readQueue addObject:packet];
			[self maybeDequeueRead];
		}
	}});
	
	// Do not rely on the block being run in order to release the packet,
	// as the queue might get released without the block completing.
}

- (float)progressOfReadReturningTag:(long *)tagPtr bytesDone:(NSUInteger *)donePtr total:(NSUInteger *)totalPtr
{
	__block float result = 0.0F;
	
	dispatch_block_t block = ^{
		
		if (!currentRead || ![currentRead isKindOfClass:[GCDAsyncReadPacket class]])
		{
			// We're not reading anything right now.
			
			if (tagPtr != NULL)   *tagPtr = 0;
			if (donePtr != NULL)  *donePtr = 0;
			if (totalPtr != NULL) *totalPtr = 0;
			
			result = NAN;
		}
		else
		{
			// It's only possible to know the progress of our read if we're reading to a certain length.
			// If we're reading to data, we of course have no idea when the data will arrive.
			// If we're reading to timeout, then we have no idea when the next chunk of data will arrive.
			
			NSUInteger done = currentRead->bytesDone;
			NSUInteger total = currentRead->readLength;
			
			if (tagPtr != NULL)   *tagPtr = currentRead->tag;
			if (donePtr != NULL)  *donePtr = done;
			if (totalPtr != NULL) *totalPtr = total;
			
			if (total > 0)
				result = (float)done / (float)total;
			else
				result = 1.0F;
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

/**
 * This method starts a new read, if needed.
 * 
 * It is called when:
 * - a user requests a read
 * - after a read request has finished (to handle the next request)
 * - immediately after the socket opens to handle any pending requests
 * 
 * This method also handles auto-disconnect post read/write completion.
**/
//让读任务离队，开始执行这条读任务
- (void)maybeDequeueRead
{
	LogTrace();
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	// If we're not currently processing a read AND we have an available read stream
    
    //如果当前读的包为空，而且flag为已连接
	if ((currentRead == nil) && (flags & kConnected))
	{
        //如果读的queue大于0 （里面装的是我们封装的GCDAsyncReadPacket数据包）
		if ([readQueue count] > 0)
		{
			// Dequeue the next object in the write queue
            //使得下一个对象从写的queue中离开
            
            //从readQueue中拿到第一个写的数据
			currentRead = [readQueue objectAtIndex:0];
            //移除
			[readQueue removeObjectAtIndex:0];
			
            //我们的数据包，如果是GCDAsyncSpecialPacket这种类型，这个包里装了TLS的一些设置
            //如果是这种类型的数据，那么我们就进行TLS
			if ([currentRead isKindOfClass:[GCDAsyncSpecialPacket class]])
			{
				LogVerbose(@"Dequeued GCDAsyncSpecialPacket");
				
				// Attempt to start TLS
                //标记flag为正在读取TLS
				flags |= kStartingReadTLS;
				
				// This method won't do anything unless both kStartingReadTLS and kStartingWriteTLS are set
                //只有读写都开启了TLS,才会做TLS认证
				[self maybeStartTLS];
			}
			else
			{
				LogVerbose(@"Dequeued GCDAsyncReadPacket");
				
				// Setup read timer (if needed)
                //设置读的任务超时，每次延时的时候还会调用 [self doReadData];
				[self setupReadTimerWithTimeout:currentRead->timeout];
				
				// Immediately read, if possible
                //读取数据
				[self doReadData];
			}
		}
        
        //读的队列没有数据，标记flag为，读了没有数据则断开连接状态
		else if (flags & kDisconnectAfterReads)
		{
            //如果标记有写然后断开连接
			if (flags & kDisconnectAfterWrites)
			{
                //如果写的队列为0，而且写为空
				if (([writeQueue count] == 0) && (currentWrite == nil))
				{
                    //断开连接
					[self closeWithError:nil];
				}
			}
			else
			{
                //断开连接
				[self closeWithError:nil];
			}
		}
        //如果有安全socket。
		else if (flags & kSocketSecure)
		{
            //
			[self flushSSLBuffers];
			
			// Edge case:
			// 
			// We just drained all data from the ssl buffers,
			// and all known data from the socket (socketFDBytesAvailable).
			// 
			// If we didn't get any data from this process,
			// then we may have reached the end of the TCP stream.
			// 
			// Be sure callbacks are enabled so we're notified about a disconnection.
			
            //如果可读字节数为0
			if ([preBuffer availableBytes] == 0)
			{
                //CFStream形式TLS
				if ([self usingCFStreamForTLS]) {
					// Callbacks never disabled
				}
				else {
                    //重新恢复读的source。因为每次开始读数据的时候，都会挂起读的source
					[self resumeReadSource];
				}
			}
		}
	}
}

//读的时候，如果不读数据，则去刷新SSL相关内容，把加密数据从进程缓存区中读取到prebuffer里
//缓冲ssl数据
- (void)flushSSLBuffers
{
	LogTrace();
	//断言为安全Socket
	NSAssert((flags & kSocketSecure), @"Cannot flush ssl buffers on non-secure socket");
	//如果有数据可读,直接返回
	if ([preBuffer availableBytes] > 0)
	{
		// Only flush the ssl buffers if the prebuffer is empty.
		// This is to avoid growing the prebuffer inifinitely large.
		
		return;
	}
	
	#if TARGET_OS_IPHONE
	//如果用的CFStream的TLS，把数据用CFStream的方式搬运到preBuffer中
	if ([self usingCFStreamForTLS])
	{
        //如果flag为kSecureSocketHasBytesAvailable，而且readStream有数据可读
		if ((flags & kSecureSocketHasBytesAvailable) && CFReadStreamHasBytesAvailable(readStream))
		{
			LogVerbose(@"%@ - Flushing ssl buffers into prebuffer...", THIS_METHOD);
			
            //默认一次读的大小为4KB？
			CFIndex defaultBytesToRead = (1024 * 4);
			
            //用来确保有这么大的提前buffer缓冲空间
			[preBuffer ensureCapacityForWrite:defaultBytesToRead];
			//拿到写的buffer
			uint8_t *buffer = [preBuffer writeBuffer];
			
            //从readStream中去读， 一次就读4KB，读到数据后，把数据写到writeBuffer中去   如果读的大小小于readStream中数据流大小，则会不停的触发callback，直到把数据读完为止。
			CFIndex result = CFReadStreamRead(readStream, buffer, defaultBytesToRead);
            //打印结果
			LogVerbose(@"%@ - CFReadStreamRead(): result = %i", THIS_METHOD, (int)result);
			
            //大于0，说明读写成功
			if (result > 0)
			{
                //把写的buffer头指针，移动result个偏移量
				[preBuffer didWrite:result];
			}
			
            //把kSecureSocketHasBytesAvailable 仍然可读的标记移除
			flags &= ~kSecureSocketHasBytesAvailable;
		}
		
		return;
	}
	
	#endif
	
    //不用CFStream的处理方法
    
    //先设置一个预估可用的大小
	__block NSUInteger estimatedBytesAvailable = 0;
	//更新预估可用的Block
	dispatch_block_t updateEstimatedBytesAvailable = ^{
		
		// Figure out if there is any data available to be read
		// 辨别出有任何可用的数据可以被读
		// socketFDBytesAvailable        <- Number of encrypted bytes we haven't read from the bsd socket
		// [sslPreBuffer availableBytes] <- Number of encrypted bytes we've buffered from bsd socket
		// sslInternalBufSize            <- Number of decrypted bytes SecureTransport has buffered
		// 
		// We call the variable "estimated" because we don't know how many decrypted bytes we'll get
        //我们称预估大小为可变的。因为我们无法知道有多少解密的数据我们将从sslPreBuffer中获得
		// from the encrypted bytes in the sslPreBuffer.
        
		// However, we do know this is an upper bound on the estimation.
        //然而，我们知道这个预估值的一个最大上限
		
        //预估大小 = 未读的大小 + SSL的可读大小
		estimatedBytesAvailable = socketFDBytesAvailable + [sslPreBuffer availableBytes];
		

		size_t sslInternalBufSize = 0;
        //获取到ssl上下文的大小，从sslContext中
		SSLGetBufferedReadSize(sslContext, &sslInternalBufSize);
		//再加上下文的大小
		estimatedBytesAvailable += sslInternalBufSize;
	};
	
    //调用这个Block
	updateEstimatedBytesAvailable();
	
    //如果大于0，说明有数据可读
	if (estimatedBytesAvailable > 0)
	{
        
		LogVerbose(@"%@ - Flushing ssl buffers into prebuffer...", THIS_METHOD);
		
        //标志，循环是否结束,SSL的方式是会阻塞的，直到读的数据有estimatedBytesAvailable大小为止，或者出错
		BOOL done = NO;
		do
		{
			LogVerbose(@"%@ - estimatedBytesAvailable = %lu", THIS_METHOD, (unsigned long)estimatedBytesAvailable);
			
			// Make sure there's enough room in the prebuffer
			//确保有足够的空间给prebuffer
			[preBuffer ensureCapacityForWrite:estimatedBytesAvailable];
			
			// Read data into prebuffer
			//拿到写的buffer
			uint8_t *buffer = [preBuffer writeBuffer];
			size_t bytesRead = 0;
			//用SSLRead函数去读，读到后，把数据写到buffer中，estimatedBytesAvailable为需要读的大小，bytesRead这一次实际读到字节大小，为sslContext上下文
			OSStatus result = SSLRead(sslContext, buffer, (size_t)estimatedBytesAvailable, &bytesRead);
			LogVerbose(@"%@ - read from secure socket = %u", THIS_METHOD, (unsigned)bytesRead);
			
            //把写指针后移bytesRead大小
			if (bytesRead > 0)
			{
				[preBuffer didWrite:bytesRead];
			}
			
			LogVerbose(@"%@ - prebuffer.length = %zu", THIS_METHOD, [preBuffer availableBytes]);
			
            //如果读数据出现错误
			if (result != noErr)
			{
				done = YES;
			}
			else
			{
                //在更新一下可读的数据大小
				updateEstimatedBytesAvailable();
			}
			
		}
        //只有done为NO,而且 estimatedBytesAvailable大于0才继续循环
        while (!done && estimatedBytesAvailable > 0);
	}
}

//读取数据
- (void)doReadData
{
	LogTrace();
	
	// This method is called on the socketQueue.
	// It might be called directly, or via the readSource when data is available to be read.
	
    //如果当前读取的包为空，或者flag为读取停止,这两种情况是不能去读取数据的
	if ((currentRead == nil) || (flags & kReadsPaused))
	{
		LogVerbose(@"No currentRead or kReadsPaused");
		
		// Unable to read at this time
		//如果是安全的通信，通过TLS/SSL
		if (flags & kSocketSecure)
		{
			// Here's the situation:
			// 这有一个场景
			// We have an established secure connection.
            //我们有一个确定的安全的连接
			// There may not be a currentRead, but there might be encrypted data sitting around for us.
            //可能没有立即去读，但是或许已经有加密的数据闲置在那
			// When the user does get around to issuing a read, that encrypted data will need to be decrypted.
			// 当用户开始进行一个read，这些加密的数据需要被解码
			// So why make the user wait?
            //所以为什么让用户等待？
			// We might as well get a head start on decrypting some data now.
			// 我们最好可以先进行数据解密
			// The other reason we do this has to do with detecting a socket disconnection.
            //另外的理由是，我们做这些不得不去检测socket的断开连接
			// The SSL/TLS protocol has it's own disconnection handshake.
            //SSL/TLS协议有自己的断开连接的握手
			// So when a secure socket is closed, a "goodbye" packet comes across the wire.
            //所以当一个安全连接关闭，一个“goodbye"数据包会被发送在电报中
			// We want to make sure we read the "goodbye" packet so we can properly detect the TCP disconnection.
            //我们想要确保读到“goodbye”数据包，因此我们可以确定检测到TCP连接断开
			
            //刷新SSLBuffer,把数据从链路上移到prebuffer中 (当前暂停的时候做)
			[self flushSSLBuffers];
		}
		
        //判断是否用的是 CFStream的TLS
		if ([self usingCFStreamForTLS])
		{
			// CFReadStream only fires once when there is available data.
			// It won't fire again until we've invoked CFReadStreamRead.
            //CFReadStream只会调起一次，当有可读的数据。 不会再次被调用，直到我们唤醒CFReadStreamRead。
		}
		else
		{
			// If the readSource is firing, we need to pause it
			// or else it will continue to fire over and over again.
			// 
			// If the readSource is not firing,
			// we want it to continue monitoring the socket.
			//如果读的source正在触发，我们需要去停止它，否则它会持续的被触发一遍又一遍。（要等我们把现有传过来的数据读完，才能触发下一次。）
            //如果读的source没有触发。我们想要它继续去监视socket.
            //挂起source
			if (socketFDBytesAvailable > 0)
			{
				[self suspendReadSource];
			}
		}
		return;
	}
	
    //当前数据包不为空或者flag不为kReadsPaused,正式开始读取数据
    //声明是否可读，可读数据为多大
	BOOL hasBytesAvailable = NO;
	unsigned long estimatedBytesAvailable = 0;
	
    //如果用了CFStream
	if ([self usingCFStreamForTLS])
	{
		#if TARGET_OS_IPHONE
		
		// Requested CFStream, rather than SecureTransport, for TLS (via GCDAsyncSocketUseCFStreamForTLS)
		
        //不需要得到数据大小
		estimatedBytesAvailable = 0;
        //判断如果状态可读而且有可读数据，hasBytesAvailable则为YES
		if ((flags & kSecureSocketHasBytesAvailable) && CFReadStreamHasBytesAvailable(readStream))
			hasBytesAvailable = YES;
		else
			hasBytesAvailable = NO;
		
		#endif
	}
	else
	{
        //拿到当前读到的数据大小，安全通道的和普通socket数据都和 socketFDBytesAvailable 有关
		estimatedBytesAvailable = socketFDBytesAvailable;
		//如果是安全socket
		if (flags & kSocketSecure)
		{
			// There are 2 buffers to be aware of here.
			// 这里有2个buffer需要知道，一个是sslPreBuffer还有一个是安全传输中未读取的buffer
			// We are using SecureTransport, a TLS/SSL security layer which sits atop TCP.
            //我们使用了安全的传输，一个TLS/SSL在TCP上
			// We issue a read to the SecureTranport API, which in turn issues a read to our SSLReadFunction.
            //我们发出read在安全传输的API上，其实就是发出read在SSLReadFunction上
			// Our SSLReadFunction then reads from the BSD socket and returns the encrypted data to SecureTransport.
            //我们SSLReadFunction 从BSD socket去读，并且返回加密的数据到安全传输中。
			// SecureTransport then decrypts the data, and finally returns the decrypted data back to us.
			// 然后安全传输返回解密的数据，最终把解密的数据返回给我们
			// The first buffer is one we create.
            //第一个buffe是我们创建的
			// SecureTransport often requests small amounts of data.
            //安全的传输经常需要少量的数据
			// This has to do with the encypted packets that are coming across the TCP stream.
            //他们不得不用加密包来穿过TCP流
			// But it's non-optimal to do a bunch of small reads from the BSD socket.
            //但是，这是不是最佳的，从BSD Socket上，进行一堆小的阅读
			// So our SSLReadFunction reads all available data from the socket (optimizing the sys call)
            //所以我们SSLReadFunction从socket中读取所有提供的数据（最佳的方式）
			// and may store excess in the sslPreBuffer.
            //可能在sslPreBuffer中存储超出的部分
			
            //预估的读取大小再加上 ssl中可读的
			estimatedBytesAvailable += [sslPreBuffer availableBytes];
			
			// The second buffer is within SecureTransport.
            //第二个Buffer在安全传输中
			// As mentioned earlier, there are encrypted packets coming across the TCP stream.
            //像之前提到的，这里有加密的包在TCP流中
			// SecureTransport needs the entire packet to decrypt it.
            //安全传输需要把整个包解密
			// But if the entire packet produces X bytes of decrypted data,
            //但是如果整个包只有 X字节是加密的数据
			// and we only asked SecureTransport for X/2 bytes of data,
            //而我们仅仅访问了 SecureTransport中一半字节的数据
			// it must store the extra X/2 bytes of decrypted data for the next read.
			// 我们必须存储另一半在下一次读取中
			// The SSLGetBufferedReadSize function will tell us the size of this internal buffer.
            //SSLGetBufferedReadSize方法，将告诉我们内部的buffer大小
			// From the documentation:
			// 
			// "This function does not block or cause any low-level read operations to occur."
			//从文档中：这个方法不会阻塞和引起低级别的读取操作发生
            
			size_t sslInternalBufSize = 0;
            //拿到SSL上下文中的大小,也就是计算我们能从SSLReead中能获取到的数据大小
			SSLGetBufferedReadSize(sslContext, &sslInternalBufSize);
			//加到预估大小中
			estimatedBytesAvailable += sslInternalBufSize;
		}
		//如果 estimatedBytesAvailable 大于0 为YES
		hasBytesAvailable = (estimatedBytesAvailable > 0);
	}
	
    //如果没有数据可读
	if ((hasBytesAvailable == NO) && ([preBuffer availableBytes] == 0))
	{
		LogVerbose(@"No data available to read...");
		
		// No data available to read.
		//而且不是用CFStream
		if (![self usingCFStreamForTLS])
		{
			// Need to wait for readSource to fire and notify us of
			// available data in the socket's internal read buffer.
			//恢复读的source
			[self resumeReadSource];
		}
		return;
	}
	//如果开始 kStartingReadTLS,说明正在准备握手，那么我们不能进行读取操作，要直接返回
	if (flags & kStartingReadTLS)
	{
		LogVerbose(@"Waiting for SSL/TLS handshake to complete");
		
		// The readQueue is waiting for SSL/TLS handshake to complete.
		//如果正在写的TLS，如果上一次是阻塞错误，那么在重新去握手，（防止一次握手阻塞而失败导致不再握手）
		if (flags & kStartingWriteTLS)
		{
            //如果用的是非CFStreamTLS,即安全的TLS  而且上一次握手错误为 IO阻塞的
			if ([self usingSecureTransportForTLS] && lastSSLHandshakeError == errSSLWouldBlock)
			{
				// We are in the process of a SSL Handshake.
				// We were waiting for incoming data which has just arrived.
                //SSL的握手
				[self ssl_continueSSLHandshake];
			}
		}
		else
		{
			// We are still waiting for the writeQueue to drain and start the SSL/TLS process.
			// We now know data is available to read.
			
            //如果当前不是CFStream的方式
			if (![self usingCFStreamForTLS])
			{
				// Suspend the read source or else it will continue to fire nonstop.
                //挂起读的queue
				[self suspendReadSource];
			}
		}
		
		return;
	}
	
    //是否完成读的操作
	BOOL done        = NO;  // Completed read operation
    //错误
	NSError *error   = nil; // Error occurred
	
    //当前总读的数据量
	NSUInteger totalBytesReadForCurrentRead = 0;
	
	// 
	// STEP 1 - READ FROM PREBUFFER
	// 
	//先从提前缓冲区去读，如果缓冲区可读大小大于0
	if ([preBuffer availableBytes] > 0)
	{
		// There are 3 types of read packets:
		// 
		// 1) Read all available data.
		// 2) Read a specific length of data.
		// 3) Read up to a particular terminator.
		//3种类型的读法，1、全读、2、读取特定长度、3、读取到一个明确的界限
        
		NSUInteger bytesToCopy;
		
        //如果当前读的数据界限不为空
		if (currentRead->term != nil)
		{
			// Read type #3 - read up to a terminator
			//直接读到界限
			bytesToCopy = [currentRead readLengthForTermWithPreBuffer:preBuffer found:&done];
		}
		else
		{
			// Read type #1 or #2
			//读取数据，读到指定长度或者数据包的长度为止
			bytesToCopy = [currentRead readLengthForNonTermWithHint:[preBuffer availableBytes]];
		}
		
		// Make sure we have enough room in the buffer for our read.
		//从上两步拿到我们需要读的长度，去看看有没有空间去存储
		[currentRead ensureCapacityForAdditionalDataOfLength:bytesToCopy];
		
		// Copy bytes from prebuffer into packet buffer

        //拿到我们需要追加数据的指针位置
        //当前读的数据 + 开始偏移 + 已经读完的？？
		uint8_t *buffer = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset +
		                                                                  currentRead->bytesDone;
		//从prebuffer处复制过来数据，bytesToCopy长度
		memcpy(buffer, [preBuffer readBuffer], bytesToCopy);
		
		// Remove the copied bytes from the preBuffer
        //从preBuffer移除掉已经复制的数据
		[preBuffer didRead:bytesToCopy];
		
        
		LogVerbose(@"copied(%lu) preBufferLength(%zu)", (unsigned long)bytesToCopy, [preBuffer availableBytes]);
		
		// Update totals
		
        //已读的数据加上
		currentRead->bytesDone += bytesToCopy;
        //当前已读的数据加上
		totalBytesReadForCurrentRead += bytesToCopy;
		
		// Check to see if the read operation is done
		//判断是不是读完了
		if (currentRead->readLength > 0)
		{
			// Read type #2 - read a specific length of data
			//如果已读 == 需要读的长度，说明已经读完
			done = (currentRead->bytesDone == currentRead->readLength);
		}
        //判断界限标记
		else if (currentRead->term != nil)
		{
			// Read type #3 - read up to a terminator
			
			// Our 'done' variable was updated via the readLengthForTermWithPreBuffer:found: method
			//如果没做完，且读的最大长度大于0，去判断是否溢出
			if (!done && currentRead->maxLength > 0)
			{
				// We're not done and there's a set maxLength.
				// Have we reached that maxLength yet?
				
                //如果已读的大小大于最大的大小，则报溢出错误
				if (currentRead->bytesDone >= currentRead->maxLength)
				{
					error = [self readMaxedOutError];
				}
			}
		}
		else
		{
			// Read type #1 - read all available data
			// 
			// We're done as soon as
			// - we've read all available data (in prebuffer and socket)
			// - we've read the maxLength of read packet.
			//判断已读大小和最大大小是否相同，相同则读完
			done = ((currentRead->maxLength > 0) && (currentRead->bytesDone == currentRead->maxLength));
		}
		
	}
	
	// 
	// STEP 2 - READ FROM SOCKET
	// 从socket中去读取
	
    //是否读到EOFException ，这个错误指的是文件结尾了还在继续读，就会导致这个错误被抛出
	BOOL socketEOF = (flags & kSocketHasReadEOF) ? YES : NO;  // Nothing more to read via socket (end of file)
    
    //如果没完成，且没错，没读到结尾，且没有可读数据了
	BOOL waiting   = !done && !error && !socketEOF && !hasBytesAvailable; // Ran out of data, waiting for more
    
    //如果没完成，且没错，没读到结尾，有可读数据
	if (!done && !error && !socketEOF && hasBytesAvailable)
	{
        //断言，有可读数据
		NSAssert(([preBuffer availableBytes] == 0), @"Invalid logic");
        //是否读到preBuffer中去
        BOOL readIntoPreBuffer = NO;
		uint8_t *buffer = NULL;
		size_t bytesRead = 0;
		
        //如果flag标记为安全socket
		if (flags & kSocketSecure)
		{
            //如果使用CFStream
			if ([self usingCFStreamForTLS])
			{
				#if TARGET_OS_IPHONE
				
				// Using CFStream, rather than SecureTransport, for TLS
				//默认读的大小32KB
				NSUInteger defaultReadLength = (1024 * 32);
				
                //决定我们读的字节大小，和是否使用prebuffer
				NSUInteger bytesToRead = [currentRead optimalReadLengthWithDefault:defaultReadLength
				                                                   shouldPreBuffer:&readIntoPreBuffer];
				
				// Make sure we have enough room in the buffer for our read.
				//
				// We are either reading directly into the currentRead->buffer,
				// or we're reading into the temporary preBuffer.
				//如果使用preBuffer，则去确保有这么大的空间来存
				if (readIntoPreBuffer)
				{
					[preBuffer ensureCapacityForWrite:bytesToRead];
					//拿到写的buffer
					buffer = [preBuffer writeBuffer];
				}
                //不用prebuffer
				else
				{
                    //确保大小，其实不用。。
					[currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
					
                    //获取到当前buffer上次写到的偏移位置
					buffer = (uint8_t *)[currentRead->buffer mutableBytes]
					       + currentRead->startOffset
					       + currentRead->bytesDone;
				}
				
				// Read data into buffer
                
#pragma mark - 开始读取数据 CFStream
				//从readStream中读取数据，到buffer中
				CFIndex result = CFReadStreamRead(readStream, buffer, (CFIndex)bytesToRead);
				LogVerbose(@"CFReadStreamRead(): result = %i", (int)result);
				
                //读取失败
				if (result < 0)
				{
					error = (__bridge_transfer NSError *)CFReadStreamCopyError(readStream);
				}
                // 读取抛出了EOFException，到数据边界了
				else if (result == 0)
				{
					socketEOF = YES;
				}
                //正常读取
				else
				{
					waiting = YES;
					bytesRead = (size_t)result;
				}
				
				// We only know how many decrypted bytes were read.
				// The actual number of bytes read was likely more due to the overhead of the encryption.
				// So we reset our flag, and rely on the next callback to alert us of more data.
                
                //移除仍然有数据可读的标记
				flags &= ~kSecureSocketHasBytesAvailable;
				
				#endif
			}
			else
			{
                //用安全传输来
				// Using SecureTransport for TLS
				//
				// We know:
				// - how many bytes are available on the socket
				// - how many encrypted bytes are sitting in the sslPreBuffer
				// - how many decypted bytes are sitting in the sslContext
				//
				// But we do NOT know:
				// - how many encypted bytes are sitting in the sslContext
				//
				// So we play the regular game of using an upper bound instead.
				
                //也是默认32KB
				NSUInteger defaultReadLength = (1024 * 32);
				
                //如果默认大小小于预估的大小，则让默认大小的 =  预估大小 + 16KB ，16KB干嘛用的？？
				if (defaultReadLength < estimatedBytesAvailable) {
					defaultReadLength = estimatedBytesAvailable + (1024 * 16);
				}
				//去要读的大小，还有是否走Prebuffer
				NSUInteger bytesToRead = [currentRead optimalReadLengthWithDefault:defaultReadLength
				                                                   shouldPreBuffer:&readIntoPreBuffer];
				
                //如果要读的大小大于最大值 ，则让其等于最大值
				if (bytesToRead > SIZE_MAX) { // NSUInteger may be bigger than size_t
					bytesToRead = SIZE_MAX;
				}
				
				// Make sure we have enough room in the buffer for our read.
				//
				// We are either reading directly into the currentRead->buffer,
				// or we're reading into the temporary preBuffer.
				
                //还是去确保最大空间，并且拿到写的头指针
				if (readIntoPreBuffer)
				{
					[preBuffer ensureCapacityForWrite:bytesToRead];
					
					buffer = [preBuffer writeBuffer];
				}
				else
				{
					[currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
					
					buffer = (uint8_t *)[currentRead->buffer mutableBytes]
					       + currentRead->startOffset
					       + currentRead->bytesDone;
				}
				
				// The documentation from Apple states:
				// 
				//     "a read operation might return errSSLWouldBlock,
				//      indicating that less data than requested was actually transferred"
				// 
				// However, starting around 10.7, the function will sometimes return noErr,
				// even if it didn't read as much data as requested. So we need to watch out for that.
				
				OSStatus result;
            
#pragma mark - 开始读取数据 SSLRead
                //循环去读
				do
				{
                    //拿到当前写到的buffer位置
                    //头指针 + 读了的大小
					void *loop_buffer = buffer + bytesRead;
                    
                    //得到还需要读的大小
					size_t loop_bytesToRead = (size_t)bytesToRead - bytesRead;
                    //设置这一次循环读的进度
					size_t loop_bytesRead = 0;
                    
					//用ssl方式去读取数据，头指针为loop_buffer，大小为loop_bytesToRead，进度为loop_bytesRead
					result = SSLRead(sslContext, loop_buffer, loop_bytesToRead, &loop_bytesRead);
					LogVerbose(@"read from secure socket = %u", (unsigned)loop_bytesRead);
					
                    //读了的大小加进度
					bytesRead += loop_bytesRead;
					
				}
                //如果没出错，且读的大小小于需要读的大小，就一直循环
                while ((result == noErr) && (bytesRead < bytesToRead));
				
				//如果出错
				if (result != noErr)
				{
                    //如果是IO阻塞的错误， waiting
					if (result == errSSLWouldBlock)
						waiting = YES;
					else
					{
                        //如果是SSL连接断开的错误
						if (result == errSSLClosedGraceful || result == errSSLClosedAbort)
						{
							// We've reached the end of the stream.
							// Handle this the same way we would an EOF from the socket.
                            //说明到边界了
							socketEOF = YES;
                            //把错误赋值给SSLErrCode
							sslErrCode = result;
						}
						else
						{
                            //直接拿到SSL数据错误
							error = [self sslError:result];
						}
					}
					// It's possible that bytesRead > 0, even if the result was errSSLWouldBlock.
                    //很有可能bytesRead中有数据，即使结果是IO阻塞的错误
					// This happens when the SSLRead function is able to read some data,
					// but not the entire amount we requested.
					
                    
					if (bytesRead <= 0)
					{
						bytesRead = 0;
					}
				}
				//不要修改 socketFDBytesAvailable 可读数据大小，因为这个会在 SSLReadFunction中被修改
				// Do not modify socketFDBytesAvailable.
				// It will be updated via the SSLReadFunction().
			}
		}
		else
		{
			// Normal socket operation
			//普通的socket 操作
            
			NSUInteger bytesToRead;
			
			// There are 3 types of read packets:
			//
			// 1) Read all available data.
			// 2) Read a specific length of data.
			// 3) Read up to a particular terminator.
			
            //和上面类似，读取到边界标记？？不是吧
			if (currentRead->term != nil)
			{
				// Read type #3 - read up to a terminator
				
                //读这个长度，如果到maxlength，就用maxlength。看如果可用空间大于需要读的空间，则不用prebuffer
				bytesToRead = [currentRead readLengthForTermWithHint:estimatedBytesAvailable
				                                     shouldPreBuffer:&readIntoPreBuffer];
			}
            
			else
			{
				// Read type #1 or #2
				//直接读这个长度，如果到maxlength，就用maxlength
				bytesToRead = [currentRead readLengthForNonTermWithHint:estimatedBytesAvailable];
			}
			
            //大于最大值，则先读最大值
			if (bytesToRead > SIZE_MAX) { // NSUInteger may be bigger than size_t (read param 3)
				bytesToRead = SIZE_MAX;
			}
			
			// Make sure we have enough room in the buffer for our read.
			//
			// We are either reading directly into the currentRead->buffer,
			// or we're reading into the temporary preBuffer.
			
			if (readIntoPreBuffer)
			{
				[preBuffer ensureCapacityForWrite:bytesToRead];
				
				buffer = [preBuffer writeBuffer];
			}
			else
			{
				[currentRead ensureCapacityForAdditionalDataOfLength:bytesToRead];
				
				buffer = (uint8_t *)[currentRead->buffer mutableBytes]
				       + currentRead->startOffset
				       + currentRead->bytesDone;
			}
			
			// Read data into buffer
			
			int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
#pragma mark - 开始读取数据，最普通的形式 read
            
            //读数据
			ssize_t result = read(socketFD, buffer, (size_t)bytesToRead);
			LogVerbose(@"read from socket = %i", (int)result);
            //读取错误
			if (result < 0)
			{
                //EWOULDBLOCK IO阻塞
				if (errno == EWOULDBLOCK)
                    //先等待
					waiting = YES;
				else
                    //得到错误
					error = [self errnoErrorWithReason:@"Error in read() function"];
				//把可读取的长度设置为0
				socketFDBytesAvailable = 0;
			}
            //读到边界了
			else if (result == 0)
			{
				socketEOF = YES;
				socketFDBytesAvailable = 0;
			}
            //正常
			else
			{
                //设置读到的数据长度
				bytesRead = result;
				
                //如果读到的数据小于应该读的长度，说明这个包没读完
				if (bytesRead < bytesToRead)
				{
					// The read returned less data than requested.
					// This means socketFDBytesAvailable was a bit off due to timing,
					// because we read from the socket right when the readSource event was firing.
					socketFDBytesAvailable = 0;
				}
                //正常
				else
				{
                    //如果 socketFDBytesAvailable比读了的数据小的话，直接置为0
					if (socketFDBytesAvailable <= bytesRead)
						socketFDBytesAvailable = 0;
                    //减去已读大小
					else
						socketFDBytesAvailable -= bytesRead;
				}
				//如果 socketFDBytesAvailable 可读数量为0，把读的状态切换为等待
				if (socketFDBytesAvailable == 0)
				{
					waiting = YES;
				}
			}
		}
		
        //如果这次读的字节大于0
		if (bytesRead > 0)
		{
			// Check to see if the read operation is done
			//检查这个包的数据是否读完，用readLength来读的
			if (currentRead->readLength > 0)
			{
				// Read type #2 - read a specific length of data
				// 
				// Note: We should never be using a prebuffer when we're reading a specific length of data.
                //我们读取固定大小的时候是永远不用写到prebuffer中去的
                
				//断言,是不需要写到prebuffer中去的
				NSAssert(readIntoPreBuffer == NO, @"Invalid logic");
				
                //加上读的数量
				currentRead->bytesDone += bytesRead;
                //把这一次读的数量加上来
				totalBytesReadForCurrentRead += bytesRead;
				//判断是否已读完
				done = (currentRead->bytesDone == currentRead->readLength);
			}
            
            //用边界来读的
			else if (currentRead->term != nil)
			{
				// Read type #3 - read up to a terminator
				//如果是往buffer中读的
				if (readIntoPreBuffer)
				{
					// We just read a big chunk of data into the preBuffer
					
                    //移动writeBuffer的指针
					[preBuffer didWrite:bytesRead];
					LogVerbose(@"read data into preBuffer - preBuffer.length = %zu", [preBuffer availableBytes]);
					
					// Search for the terminating sequence
					
                    //拿到需要读取的大小，根据term，并且判断是否已读完
					NSUInteger bytesToCopy = [currentRead readLengthForTermWithPreBuffer:preBuffer found:&done];
					LogVerbose(@"copying %lu bytes from preBuffer", (unsigned long)bytesToCopy);
					
					// Ensure there's room on the read packet's buffer
					//确保有这么大的空间
					[currentRead ensureCapacityForAdditionalDataOfLength:bytesToCopy];
					
					// Copy bytes from prebuffer into read buffer
					
					uint8_t *readBuf = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset
					                                                                 + currentRead->bytesDone;
					
#pragma mark - 把数据从preBuffer中移到currentRead上
					memcpy(readBuf, [preBuffer readBuffer], bytesToCopy);
					
					// Remove the copied bytes from the prebuffer
                    //标记已经读了这么多数据
					[preBuffer didRead:bytesToCopy];
					LogVerbose(@"preBuffer.length = %zu", [preBuffer availableBytes]);
					
					// Update totals
					currentRead->bytesDone += bytesToCopy;
					totalBytesReadForCurrentRead += bytesToCopy;
					
					// Our 'done' variable was updated via the readLengthForTermWithPreBuffer:found: method above
				}
                
                //没有用prebuffer
				else
				{
					// We just read a big chunk of data directly into the packet's buffer.
					// We need to move any overflow into the prebuffer.
					//我们需要把数据流向prebuffer？
                    
                    //拿到粘包长度，（为溢出长度，溢出的我们要写到prebuffer中去。给下一个包去读）
					NSInteger overflow = [currentRead searchForTermAfterPreBuffering:bytesRead];
					
                    //如果为0，说明完全匹配
					if (overflow == 0)
					{
						// Perfect match!
						// Every byte we read stays in the read buffer,
						// and the last byte we read was the last byte of the term.
						//加上这次读取的字节数
						currentRead->bytesDone += bytesRead;
                        //总的读取字节数
						totalBytesReadForCurrentRead += bytesRead;
                        //标志读取完成
						done = YES;
					}
                    
                    //说明读取的数据总长度比当前包大（粘包）
					else if (overflow > 0)
					{
						// The term was found within the data that we read,
						// and there are extra bytes that extend past the end of the term.
						// We need to move these excess bytes out of the read packet and into the prebuffer.
						
                        //当前包内的长度
						NSInteger underflow = bytesRead - overflow;
						
						// Copy excess data into preBuffer
						
						LogVerbose(@"copying %ld overflow bytes into preBuffer", (long)overflow);
                        //确保preBuffer有这么大的大小
						[preBuffer ensureCapacityForWrite:overflow];
						
                        //把buffer往后移，去掉重合的数据大小
						uint8_t *overflowBuffer = buffer + underflow;
                        
                        //写到writeBuffer中，长度为 overflow（非重合部分）
						memcpy([preBuffer writeBuffer], overflowBuffer, overflow);
						//后移写指针
						[preBuffer didWrite:overflow];
						LogVerbose(@"preBuffer.length = %zu", [preBuffer availableBytes]);
						
						// Note: The completeCurrentRead method will trim the buffer for us.
						
                        //加上已读的大小（非粘包的）
						currentRead->bytesDone += underflow;
                        //这次总共读取的大小
						totalBytesReadForCurrentRead += underflow;
                        //当前读取完成
						done = YES;
					}
                    //数据还没达到边界
					else
					{
						// The term was not found within the data that we read.
						//已读的加上 bytesRead
						currentRead->bytesDone += bytesRead;
						totalBytesReadForCurrentRead += bytesRead;
                        //标记为未完成
						done = NO;
					}
				}
				
                //如果未完成 而且当前包的数据包最大长度大于0
				if (!done && currentRead->maxLength > 0)
				{
					// We're not done and there's a set maxLength.
					// Have we reached that maxLength yet?
					//判断写的大小 是否达到包的最大值
					if (currentRead->bytesDone >= currentRead->maxLength)
					{
                        //得到读取溢出的错误
						error = [self readMaxedOutError];
					}
				}
			}
            
            //没边界，没给定长度（无法判断当前包结尾）
			else
			{
				// Read type #1 - read all available data
				//如果从prebuffer中读取
				if (readIntoPreBuffer)
				{
					// We just read a chunk of data into the preBuffer
					
                    //指针后移
					[preBuffer didWrite:bytesRead];
					
					// Now copy the data into the read packet.
					// 
					// Recall that we didn't read directly into the packet's buffer to avoid
					// over-allocating memory since we had no clue how much data was available to be read.
					// 
					// Ensure there's room on the read packet's buffer
					
                    //确保currentRead中有bytesRead大小可用
					[currentRead ensureCapacityForAdditionalDataOfLength:bytesRead];
					
					// Copy bytes from prebuffer into read buffer
					
					uint8_t *readBuf = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset
					                                                                 + currentRead->bytesDone;
					
                    //拿到指针赋值
					memcpy(readBuf, [preBuffer readBuffer], bytesRead);
					
					// Remove the copied bytes from the prebuffer
					//标记读了这么多数据
                    [preBuffer didRead:bytesRead];
					
					// Update totals
                    //更新已读
					currentRead->bytesDone += bytesRead;
					totalBytesReadForCurrentRead += bytesRead;
				}
                //在currentRead中的话直接加就行
				else
				{
					currentRead->bytesDone += bytesRead;
					totalBytesReadForCurrentRead += bytesRead;
				}
				//因为无法判断结尾，所以每次读都会直接标记为YES，即一个包完成
				done = YES;
			}
			
		} // if (bytesRead > 0)
		
	} // if (!done && !error && !socketEOF && hasBytesAvailable)
	
	
    //如果未完成，而且没有应读长度和边界符
	if (!done && currentRead->readLength == 0 && currentRead->term == nil)
	{
		// Read type #1 - read all available data
		// 
		// We might arrive here if we read data from the prebuffer but not from the socket.
		//只要当前总共读的数量大于0，就认为完成了，因为无从判断
		done = (totalBytesReadForCurrentRead > 0);
	}
	
	// Check to see if we're done, or if we've made progress
	//检查是否读完
	if (done)
	{
        //完成这次数据的读取
		[self completeCurrentRead];
		//如果没出错，没有到边界，prebuffer中还有可读数据
		if (!error && (!socketEOF || [preBuffer availableBytes] > 0))
		{
            //让读操作离队,继续进行下一次读取
			[self maybeDequeueRead];
		}
	}
    
    //如果这次读的数量大于0
	else if (totalBytesReadForCurrentRead > 0)
	{
		// We're not done read type #2 or #3 yet, but we have read in some bytes

		__strong id theDelegate = delegate;
		
        //如果响应读数据进度的代理
		if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReadPartialDataOfLength:tag:)])
		{
			long theReadTag = currentRead->tag;
			
            //代理queue中回调出去
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
				
				[theDelegate socket:self didReadPartialDataOfLength:totalBytesReadForCurrentRead tag:theReadTag];
			}});
		}
	}
	
	// Check for errors
	//检查错误
	if (error)
	{
        //如果有错直接报错断开连接
		[self closeWithError:error];
	}
    //如果是读到边界错误
	else if (socketEOF)
	{
		[self doReadEOF];
	}
    
    //如果是等待
	else if (waiting)
	{
        //如果用的是CFStream,则读取数据和source无关
        //非CFStream形式
		if (![self usingCFStreamForTLS])
		{
			// Monitor the socket for readability (if we're not already doing so)
            //重新恢复source
			[self resumeReadSource];
		}
	}
	// Do not add any code here without first adding return statements in the error cases above.
}


//读到EOFException，边界错误
- (void)doReadEOF
{
	LogTrace();
	
	// This method may be called more than once.
	// If the EOF is read while there is still data in the preBuffer,
	// then this method may be called continually after invocations of doReadData to see if it's time to disconnect.
    //这个方法可能被调用很多次，如果读到EOF的时候，还有数据在prebuffer中，在调用doReadData之后？？ 这个方法可能被持续的调用
    
	//标记为读EOF
	flags |= kSocketHasReadEOF;
	
    //如果是安全socket
	if (flags & kSocketSecure)
	{
		// If the SSL layer has any buffered data, flush it into the preBuffer now.
		//去刷新sslbuffer中的数据
		[self flushSSLBuffers];
	}
	
    //标记是否应该断开连接
	BOOL shouldDisconnect = NO;
	NSError *error = nil;
	
    //如果状态为开始读写TLS
	if ((flags & kStartingReadTLS) || (flags & kStartingWriteTLS))
	{
		// We received an EOF during or prior to startTLS.
		// The SSL/TLS handshake is now impossible, so this is an unrecoverable situation.
        //我们得到EOF在开启TLS之前，这个TLS握手是不可能的，因此这是不可恢复的错误
		
        //标记断开连接
		shouldDisconnect = YES;
		//如果是安全的TLS，赋值错误
		if ([self usingSecureTransportForTLS])
		{
			error = [self sslError:errSSLClosedAbort];
		}
	}
    //如果是读流关闭状态
	else if (flags & kReadStreamClosed)
	{
		// The preBuffer has already been drained.
        //前置缓冲已经用完
		// The config allows half-duplex connections.
        //这个设置允许半双工连接
		// We've previously checked the socket, and it appeared writeable.
        //我们可以提前检查socket，它出现可读，我们标记读流为关闭，而且通知代理
		// So we marked the read stream as closed and notified the delegate.
		//
		// As per the half-duplex contract, the socket will be closed when a write fails,
        //随着每个半双工连接，当一个写失败这个socket将会关闭、或者手动的关闭
		// or when the socket is manually closed.
		
        //不应该被关闭
		shouldDisconnect = NO;
	}
	else if ([preBuffer availableBytes] > 0)
	{
		LogVerbose(@"Socket reached EOF, but there is still data available in prebuffer");
		
		// Although we won't be able to read any more data from the socket,
		// there is existing data that has been prebuffered that we can read.
		
        //仍然有数据可读的时候不关闭
		shouldDisconnect = NO;
	}
	else if (config & kAllowHalfDuplexConnection)
	{
		// We just received an EOF (end of file) from the socket's read stream.
        //我们从读流中收到EOF
		// This means the remote end of the socket (the peer we're connected to)
        //说明远端的socket关闭了
		// has explicitly stated that it will not be sending us any more data.
		// 明确的状态表明它不会再给我们发送任何数据
		// Query the socket to see if it is still writeable. (Perhaps the peer will continue reading data from us)
		//询问socket它是否仍然可读（可能仍然持续的去读我们的数据）
        
        //拿到socket
		int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
		
        //轮询用的结构体
        
        /*
         struct pollfd {
         int fd;        //文件描述符
         short events;  //要求查询的事件掩码  监听的
         short revents; //返回的事件掩码   实际发生的
         };
         */
        
		struct pollfd pfd[1];
		pfd[0].fd = socketFD;
        //写数据不会导致阻塞。
		pfd[0].events = POLLOUT;
        //这个为当前实际发生的事情
		pfd[0].revents = 0;
		
        /*
         poll函数使用pollfd类型的结构来监控一组文件句柄，ufds是要监控的文件句柄集合，nfds是监控的文件句柄数量，timeout是等待的毫秒数，这段时间内无论I/O是否准备好，poll都会返回。timeout为负数表示无线等待，timeout为0表示调用后立即返回。执行结果：为0表示超时前没有任何事件发生；-1表示失败；成功则返回结构体中revents不为0的文件描述符个数。pollfd结构监控的事件类型如下：
         int poll(struct pollfd *ufds, unsigned int nfds, int timeout);
         */
        //阻塞的，但是timeout为0，则不阻塞，直接返回
		poll(pfd, 1, 0);
		
        //如果被触发的事件是写数据
		if (pfd[0].revents & POLLOUT)
		{
			// Socket appears to still be writeable
			
            //则标记为不关闭
			shouldDisconnect = NO;
            //标记为读流关闭
			flags |= kReadStreamClosed;
			
			// Notify the delegate that we're going half-duplex
			//通知代理，我们开始半双工
			__strong id theDelegate = delegate;

            //调用已经关闭读流的代理方法
			if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidCloseReadStream:)])
			{
				dispatch_async(delegateQueue, ^{ @autoreleasepool {
					
					[theDelegate socketDidCloseReadStream:self];
				}});
			}
		}
		else
		{
            //标记为断开
			shouldDisconnect = YES;
		}
	}
	else
	{
		shouldDisconnect = YES;
	}
	
	//如果应该断开
	if (shouldDisconnect)
	{
		if (error == nil)
		{
            //判断是否是安全TLS传输
			if ([self usingSecureTransportForTLS])
			{
                ///标记错误信息
				if (sslErrCode != noErr && sslErrCode != errSSLClosedGraceful)
				{
					error = [self sslError:sslErrCode];
				}
				else
				{
					error = [self connectionClosedError];
				}
			}
			else
			{
				error = [self connectionClosedError];
			}
		}
        //关闭socket
		[self closeWithError:error];
	}
    //不断开
	else
	{
        //如果不是用CFStream流
		if (![self usingCFStreamForTLS])
		{
			// Suspend the read source (if needed)
			//挂起读source
			[self suspendReadSource];
		}
	}
}

//完成了这次的读数据
- (void)completeCurrentRead
{
	LogTrace();
	//断言currentRead
	NSAssert(currentRead, @"Trying to complete current read when there is no current read.");
	
	//结果数据
	NSData *result = nil;
	
    //如果是我们自己创建的Buffer
	if (currentRead->bufferOwner)
	{
		// We created the buffer on behalf of the user.
		// Trim our buffer to be the proper size.
        //修剪buffer到合适的大小
        //把大小设置到我们读取到的大小
		[currentRead->buffer setLength:currentRead->bytesDone];
		//赋值给result
		result = currentRead->buffer;
	}
	else
	{
		// We did NOT create the buffer.
		// The buffer is owned by the caller.
		// Only trim the buffer if we had to increase its size.
		//这是调用者的data，我们只会去加大尺寸
		if ([currentRead->buffer length] > currentRead->originalBufferLength)
		{
            //拿到的读的size
			NSUInteger readSize = currentRead->startOffset + currentRead->bytesDone;
            //拿到原始尺寸
			NSUInteger origSize = currentRead->originalBufferLength;
			
            //取得最大的
			NSUInteger buffSize = MAX(readSize, origSize);
			//把buffer设置为较大的尺寸
			[currentRead->buffer setLength:buffSize];
		}
		//拿到数据的头指针
		uint8_t *buffer = (uint8_t *)[currentRead->buffer mutableBytes] + currentRead->startOffset;
		
        //reslut为，从头指针开始到长度为写的长度 freeWhenDone为YES，创建完就释放buffer
		result = [NSData dataWithBytesNoCopy:buffer length:currentRead->bytesDone freeWhenDone:NO];
	}
	
	__strong id theDelegate = delegate;

#pragma mark -总算到调用代理方法，接受到数据了
	if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReadData:withTag:)])
	{
        //拿到当前的数据包
		GCDAsyncReadPacket *theRead = currentRead; // Ensure currentRead retained since result may not own buffer
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			//把result在代理queue中回调出去。
			[theDelegate socket:self didReadData:result withTag:theRead->tag];
		}});
	}
	//取消掉读取超时
	[self endCurrentRead];
}

//停止读取
- (void)endCurrentRead
{
    //取消读取的超时
	if (readTimer)
	{
		dispatch_source_cancel(readTimer);
		readTimer = NULL;
	}
	
	currentRead = nil;
}

//初始化读的超时
- (void)setupReadTimerWithTimeout:(NSTimeInterval)timeout
{
	if (timeout >= 0.0)
	{
        //生成一个定时器source
		readTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
		
		__weak GCDAsyncSocket *weakSelf = self;
		
        //句柄
		dispatch_source_set_event_handler(readTimer, ^{ @autoreleasepool {
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			__strong GCDAsyncSocket *strongSelf = weakSelf;
			if (strongSelf == nil) return_from_block;
			
            //执行超时操作
			[strongSelf doReadTimeout];
			
		#pragma clang diagnostic pop
		}});
		
		#if !OS_OBJECT_USE_OBJC
		dispatch_source_t theReadTimer = readTimer;
        
        //取消的句柄
		dispatch_source_set_cancel_handler(readTimer, ^{
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			LogVerbose(@"dispatch_release(readTimer)");
			dispatch_release(theReadTimer);
			
		#pragma clang diagnostic pop
		});
		#endif
        
		
        //定时器延时 timeout时间执行
		dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
		//间隔为永远，即只执行一次
		dispatch_source_set_timer(readTimer, tt, DISPATCH_TIME_FOREVER, 0);
		dispatch_resume(readTimer);
	}
}

//执行超时操作
- (void)doReadTimeout
{
	// This is a little bit tricky.
	// Ideally we'd like to synchronously query the delegate about a timeout extension.
	// But if we do so synchronously we risk a possible deadlock.
	// So instead we have to do so asynchronously, and callback to ourselves from within the delegate block.
    
    //因为这里用同步容易死锁，所以用异步从代理中回调
	
    //标记读暂停
	flags |= kReadsPaused;
	
	__strong id theDelegate = delegate;

    //判断是否实现了延时  补时的代理
	if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:shouldTimeoutReadWithTag:elapsed:bytesDone:)])
	{
        //拿到当前读的包
		GCDAsyncReadPacket *theRead = currentRead;
		
        //代理queue中回调
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			NSTimeInterval timeoutExtension = 0.0;
			
            //调用代理方法，拿到续的时长
			timeoutExtension = [theDelegate socket:self shouldTimeoutReadWithTag:theRead->tag
			                                                             elapsed:theRead->timeout
			                                                           bytesDone:theRead->bytesDone];
			
            //socketQueue中，做延时
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				[self doReadTimeoutWithExtension:timeoutExtension];
			}});
		}});
	}
	else
	{
		[self doReadTimeoutWithExtension:0.0];
	}
}

//做读取数据延时
- (void)doReadTimeoutWithExtension:(NSTimeInterval)timeoutExtension
{
	if (currentRead)
	{
		if (timeoutExtension > 0.0)
		{
            //把超时加上
			currentRead->timeout += timeoutExtension;
			
			// Reschedule the timer
            //重新生成时间
			dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutExtension * NSEC_PER_SEC));
            //重置timer时间
			dispatch_source_set_timer(readTimer, tt, DISPATCH_TIME_FOREVER, 0);
			
			// Unpause reads, and continue
            //在把paused标记移除
			flags &= ~kReadsPaused;
            //继续去读取数据
			[self doReadData];
		}
		else
		{
            //输出读取超时，并断开连接
			LogVerbose(@"ReadTimeout");
			
			[self closeWithError:[self readTimeoutError]];
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Writing
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//写数据对外方法
- (void)writeData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag
{
	if ([data length] == 0) return;
	
    //初始化写包
	GCDAsyncWritePacket *packet = [[GCDAsyncWritePacket alloc] initWithData:data timeout:timeout tag:tag];
	
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		LogTrace();
		
		if ((flags & kSocketStarted) && !(flags & kForbidReadsWrites))
		{
			[writeQueue addObject:packet];
            //离队执行
			[self maybeDequeueWrite];
		}
	}});
	
	// Do not rely on the block being run in order to release the packet,
	// as the queue might get released without the block completing.
}

- (float)progressOfWriteReturningTag:(long *)tagPtr bytesDone:(NSUInteger *)donePtr total:(NSUInteger *)totalPtr
{
	__block float result = 0.0F;
	
	dispatch_block_t block = ^{
		
		if (!currentWrite || ![currentWrite isKindOfClass:[GCDAsyncWritePacket class]])
		{
			// We're not writing anything right now.
			
			if (tagPtr != NULL)   *tagPtr = 0;
			if (donePtr != NULL)  *donePtr = 0;
			if (totalPtr != NULL) *totalPtr = 0;
			
			result = NAN;
		}
		else
		{
			NSUInteger done = currentWrite->bytesDone;
			NSUInteger total = [currentWrite->buffer length];
			
			if (tagPtr != NULL)   *tagPtr = currentWrite->tag;
			if (donePtr != NULL)  *donePtr = done;
			if (totalPtr != NULL) *totalPtr = total;
			
			result = (float)done / (float)total;
		}
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
	
	return result;
}

/**
 * Conditionally starts a new write.
 * 
 * It is called when:
 * - a user requests a write
 * - after a write request has finished (to handle the next request)
 * - immediately after the socket opens to handle any pending requests
 * 
 * This method also handles auto-disconnect post read/write completion.
**/
- (void)maybeDequeueWrite
{
	LogTrace();
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	
	// If we're not currently processing a write AND we have an available write stream
	if ((currentWrite == nil) && (flags & kConnected))
	{
		if ([writeQueue count] > 0)
		{
			// Dequeue the next object in the write queue
			currentWrite = [writeQueue objectAtIndex:0];
			[writeQueue removeObjectAtIndex:0];
			
			//TLS
			if ([currentWrite isKindOfClass:[GCDAsyncSpecialPacket class]])
			{
				LogVerbose(@"Dequeued GCDAsyncSpecialPacket");
				
				// Attempt to start TLS
				flags |= kStartingWriteTLS;
				
				// This method won't do anything unless both kStartingReadTLS and kStartingWriteTLS are set
				[self maybeStartTLS];
			}
			else
			{
				LogVerbose(@"Dequeued GCDAsyncWritePacket");
				
				// Setup write timer (if needed)
				[self setupWriteTimerWithTimeout:currentWrite->timeout];
				
				// Immediately write, if possible
				[self doWriteData];
			}
		}
        //写超时导致的错误
		else if (flags & kDisconnectAfterWrites)
		{
            //如果没有可读任务，直接关闭socket
			if (flags & kDisconnectAfterReads)
			{
				if (([readQueue count] == 0) && (currentRead == nil))
				{
					[self closeWithError:nil];
				}
			}
			else
			{
				[self closeWithError:nil];
			}
		}
	}
}

//开始写数据 ，当前任务的
- (void)doWriteData
{
	LogTrace();
	
	// This method is called by the writeSource via the socketQueue
	
    //错误，不写
	if ((currentWrite == nil) || (flags & kWritesPaused))
	{
		LogVerbose(@"No currentWrite or kWritesPaused");
		
		// Unable to write at this time
		
        //
		if ([self usingCFStreamForTLS])
		{
			// CFWriteStream only fires once when there is available data.
			// It won't fire again until we've invoked CFWriteStreamWrite.
		}
		else
		{
			// If the writeSource is firing, we need to pause it
			// or else it will continue to fire over and over again.
			
            //如果socket中可接受写数据，防止反复触发写source，挂起
			if (flags & kSocketCanAcceptBytes)
			{
				[self suspendWriteSource];
			}
		}
		return;
	}
	
    //如果当前socket无法在写数据了
	if (!(flags & kSocketCanAcceptBytes))
	{
		LogVerbose(@"No space available to write...");
		
		// No space available to write.
		
        //如果不是cfstream
		if (![self usingCFStreamForTLS])
		{
			// Need to wait for writeSource to fire and notify us of
			// available space in the socket's internal write buffer.
            //则恢复写source，当有空间去写的时候，会触发回来
			[self resumeWriteSource];
		}
		return;
	}
	
    //如果正在进行TLS认证
	if (flags & kStartingWriteTLS)
	{
		LogVerbose(@"Waiting for SSL/TLS handshake to complete");
		
		// The writeQueue is waiting for SSL/TLS handshake to complete.
		
		if (flags & kStartingReadTLS)
		{
            //如果是安全通道，并且I/O阻塞，那么重新去握手
			if ([self usingSecureTransportForTLS] && lastSSLHandshakeError == errSSLWouldBlock)
			{
				// We are in the process of a SSL Handshake.
				// We were waiting for available space in the socket's internal OS buffer to continue writing.
			
				[self ssl_continueSSLHandshake];
			}
		}
        //说明不走`TLS`了，因为只支持写的TLS
		else
		{
			// We are still waiting for the readQueue to drain and start the SSL/TLS process.
			// We now know we can write to the socket.
			
            //挂起写source
			if (![self usingCFStreamForTLS])
			{
				// Suspend the write source or else it will continue to fire nonstop.
				[self suspendWriteSource];
			}
		}
		
		return;
	}
	
	// Note: This method is not called if currentWrite is a GCDAsyncSpecialPacket (startTLS packet)
	
    //开始写数据
    
	BOOL waiting = NO;
	NSError *error = nil;
	size_t bytesWritten = 0;
	
    //安全连接
	if (flags & kSocketSecure)
	{
        //CFStreamForTLS
		if ([self usingCFStreamForTLS])
		{
			#if TARGET_OS_IPHONE
			
			// 
			// Writing data using CFStream (over internal TLS)
			// 
			
			const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes] + currentWrite->bytesDone;
			
            //写的长度为buffer长度-已写长度
			NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone;
			
			if (bytesToWrite > SIZE_MAX) // NSUInteger may be bigger than size_t (write param 3)
			{
				bytesToWrite = SIZE_MAX;
			}
            //往writeStream中写入数据， bytesToWrite写入的长度
			CFIndex result = CFWriteStreamWrite(writeStream, buffer, (CFIndex)bytesToWrite);
			LogVerbose(@"CFWriteStreamWrite(%lu) = %li", (unsigned long)bytesToWrite, result);
		
            //写错误
			if (result < 0)
			{
				error = (__bridge_transfer NSError *)CFWriteStreamCopyError(writeStream);
			}
			else
			{
                //拿到已写字节数
				bytesWritten = (size_t)result;
				
				// We always set waiting to true in this scenario.
                //我们经常设置等待来信任这个方案
				// CFStream may have altered our underlying socket to non-blocking.
                //CFStream很可能修改socket为非阻塞
				// Thus if we attempt to write without a callback, we may end up blocking our queue.
                //因此，我们尝试去写，而不用回调。 我们可能终止我们的队列。
				waiting = YES;
			}
			
			#endif
		}
        //SSL写的方式
		else
		{
			// We're going to use the SSLWrite function.
			// 
			// OSStatus SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed)
			// 
			// Parameters:
			// context     - An SSL session context reference.
			// data        - A pointer to the buffer of data to write.
			// dataLength  - The amount, in bytes, of data to write.
			// processed   - On return, the length, in bytes, of the data actually written.
			// 
			// It sounds pretty straight-forward,
            //看起来相当直观，但是这里警告你应注意。
			// but there are a few caveats you should be aware of.
			// 
			// The SSLWrite method operates in a non-obvious (and rather annoying) manner.
			// According to the documentation:
			// 这个SSLWrite方法使用着一个不明显的方法（相当讨厌）导致了下面这些事。
			//   Because you may configure the underlying connection to operate in a non-blocking manner,
            //因为你要辨别出下层连接 操纵 非阻塞的方法，一个写的操作将返回errSSLWouldBlock，表明需要写的数据少了。
			//   a write operation might return errSSLWouldBlock, indicating that less data than requested
			//   was actually transferred. In this case, you should repeat the call to SSLWrite until some
            //在这种情况下你应该重复调用SSLWrite，直到一些其他结果被返回
			//   other result is returned.
			// This sounds perfect, but when our SSLWriteFunction returns errSSLWouldBlock,
            //这样听起来很完美，但是当SSLWriteFunction返回errSSLWouldBlock，SSLWrite返回但是却设置了进度长度？
			// then the SSLWrite method returns (with the proper errSSLWouldBlock return value),
			// but it sets processed to dataLength !!
			// 
			// In other words, if the SSLWrite function doesn't completely write all the data we tell it to,
            //另外，SSLWrite方法没有完整的写完我们给的所有数据，因此它没有告诉我们到底写了多少数据，
			// then it doesn't tell us how many bytes were actually written. So, for example, if we tell it to
            //因此。举个例子，如果我们告诉它去写256个字节，它可能只写了128个字节，但是告诉我们写了0个字节
			// write 256 bytes then it might actually write 128 bytes, but then report 0 bytes written.
			// 
			// You might be wondering:
            //你可能会觉得奇怪，如果这个方法不告诉我们写了多少字节，那么该如何去更新参数来应对下一次的SSLWrite？
			// If the SSLWrite function doesn't tell us how many bytes were written,
			// then how in the world are we supposed to update our parameters (buffer & bytesToWrite)
			// for the next time we invoke SSLWrite?
			// 
			// The answer is that SSLWrite cached all the data we told it to write,
            //答案就是，SSLWrite缓存了所有的数据我们要它写的。并且拉出这些数据，只要我们下次调用SSLWrite。
			// and it will push out that data next time we call SSLWrite.
            
			// If we call SSLWrite with new data, it will push out the cached data first, and then the new data.
            //如果我们用新的data调用SSLWrite,它会拉出这些缓存的数据，然后才轮到新数据
			// If we call SSLWrite with empty data, then it will simply push out the cached data.
			// 如果我们调用SSLWrite用一个空的数据，则它仅仅会拉出缓存数据。
			// For this purpose we're going to break large writes into a series of smaller writes.
            //为了这个目的，我们去分开一个大数据写成一连串的小数据，它允许我们去报告进度给代理。
			// This allows us to report progress back to the delegate.
			
			OSStatus result;
			
            //SSL缓存的写的数据
			BOOL hasCachedDataToWrite = (sslWriteCachedLength > 0);
            //是否有新数据要写
			BOOL hasNewDataToWrite = YES;
			
			if (hasCachedDataToWrite)
			{
				size_t processed = 0;
				
                //去写空指针，就是拉取了所有的缓存SSL数据
				result = SSLWrite(sslContext, NULL, 0, &processed);
				
                //如果写成功
				if (result == noErr)
				{
                    //拿到写的缓存长度
					bytesWritten = sslWriteCachedLength;
                    //置空缓存长度
					sslWriteCachedLength =  0;
					//判断当前需要写的buffer长度，是否和已写的大小+缓存 大小相等
					if ([currentWrite->buffer length] == (currentWrite->bytesDone + bytesWritten))
					{
						// We've written all data for the current write.
                        //相同则不需要再写新数据了
						hasNewDataToWrite = NO;
					}
				}
                //有错
				else
				{
                    //IO阻塞，等待
					if (result == errSSLWouldBlock)
					{
						waiting = YES;
					}
                    //报错
					else
					{
						error = [self sslError:result];
					}
					
					// Can't write any new data since we were unable to write the cached data.
                    //如果读写cache出错，我们暂时不能去读后面的数据
					hasNewDataToWrite = NO;
				}
			}
			
            //如果还有数据去读
			if (hasNewDataToWrite)
			{
                //拿到buffer偏移位置
				const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes]
				                                        + currentWrite->bytesDone
				                                        + bytesWritten;
				
                //得到需要读的长度
				NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone - bytesWritten;
				//如果大于最大值,就等于最大值
				if (bytesToWrite > SIZE_MAX) // NSUInteger may be bigger than size_t (write param 3)
				{
					bytesToWrite = SIZE_MAX;
				}
				
				size_t bytesRemaining = bytesToWrite;
				
                //循环值
				BOOL keepLooping = YES;
				while (keepLooping)
				{
                    //最大写的字节数？
					const size_t sslMaxBytesToWrite = 32768;
                    //得到二者小的，得到需要写的字节数
					size_t sslBytesToWrite = MIN(bytesRemaining, sslMaxBytesToWrite);
                    //已写字节数
					size_t sslBytesWritten = 0;
					
                    //将结果从buffer中写到socket上（经由了这个函数，数据就加密了）
					result = SSLWrite(sslContext, buffer, sslBytesToWrite, &sslBytesWritten);
					
                    //如果写成功
					if (result == noErr)
					{
                        //buffer指针偏移
						buffer += sslBytesWritten;
                        //加上些的数量
						bytesWritten += sslBytesWritten;
                        //减去仍需写的数量
						bytesRemaining -= sslBytesWritten;
						//判断是否需要继续循环
						keepLooping = (bytesRemaining > 0);
					}
					else
					{
                        //IO阻塞
						if (result == errSSLWouldBlock)
						{
							waiting = YES;
                            //得到缓存的大小（后续长度会被自己写到SSL缓存去）
							sslWriteCachedLength = sslBytesToWrite;
						}
						else
						{
							error = [self sslError:result];
						}
						
                        //跳出循环
						keepLooping = NO;
					}
					
				} // while (keepLooping)
				
			} // if (hasNewDataToWrite)
		}
	}
    
    //普通socket
	else
	{
		// 
		// Writing data directly over raw socket
		// 
		
        //拿到当前socket
		int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
		
        //得到指针偏移
		const uint8_t *buffer = (const uint8_t *)[currentWrite->buffer bytes] + currentWrite->bytesDone;
		
		NSUInteger bytesToWrite = [currentWrite->buffer length] - currentWrite->bytesDone;
		
		if (bytesToWrite > SIZE_MAX) // NSUInteger may be bigger than size_t (write param 3)
		{
			bytesToWrite = SIZE_MAX;
		}
		//直接写
		ssize_t result = write(socketFD, buffer, (size_t)bytesToWrite);
		LogVerbose(@"wrote to socket = %zd", result);
		
		// Check results
		if (result < 0)
		{
            //IO阻塞
			if (errno == EWOULDBLOCK)
			{
				waiting = YES;
			}
			else
			{
				error = [self errnoErrorWithReason:@"Error in write() function"];
			}
		}
		else
		{
            //得到写的大小
			bytesWritten = result;
		}
	}
	
	// We're done with our writing.
	// If we explictly ran into a situation where the socket told us there was no room in the buffer,
	// then we immediately resume listening for notifications.
	// 
	// We must do this before we dequeue another write,
	// as that may in turn invoke this method again.
	// 
	// Note that if CFStream is involved, it may have maliciously put our socket in blocking mode.
	//注意，如果用CFStream,很可能会被恶意的放置数据 阻塞socket
    
    //如果等待，则恢复写source
	if (waiting)
	{
        //把socket可接受数据的标记去掉
		flags &= ~kSocketCanAcceptBytes;
		
		if (![self usingCFStreamForTLS])
		{
            //恢复写source
			[self resumeWriteSource];
		}
	}
	
	// Check our results
	
    //判断是否完成
	BOOL done = NO;
	//判断已写大小
	if (bytesWritten > 0)
	{
		// Update total amount read for the current write
        //更新当前总共写的大小
		currentWrite->bytesDone += bytesWritten;
		LogVerbose(@"currentWrite->bytesDone = %lu", (unsigned long)currentWrite->bytesDone);
		
		// Is packet done?
        //判断当前写包是否写完
		done = (currentWrite->bytesDone == [currentWrite->buffer length]);
	}
	
    //如果完成了
	if (done)
	{
        //完成操作
		[self completeCurrentWrite];
		
		if (!error)
		{
			dispatch_async(socketQueue, ^{ @autoreleasepool{
				//开始下一次的读取任务
				[self maybeDequeueWrite];
			}});
		}
	}
    //未完成
	else
	{
		// We were unable to finish writing the data,
		// so we're waiting for another callback to notify us of available space in the lower-level output buffer.
		//如果不是等待 而且没有出错
		if (!waiting && !error)
		{
			// This would be the case if our write was able to accept some data, but not all of it.
            //这是我们写了一部分数据的情况。
            
			//去掉可接受数据的标记
			flags &= ~kSocketCanAcceptBytes;
			//再去等读source触发
			if (![self usingCFStreamForTLS])
			{
				[self resumeWriteSource];
			}
		}
		
        //如果已写大于0
		if (bytesWritten > 0)
		{
			// We're not done with the entire write, but we have written some bytes
			
			__strong id theDelegate = delegate;

            //调用写的进度代理
			if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didWritePartialDataOfLength:tag:)])
			{
				long theWriteTag = currentWrite->tag;
				
				dispatch_async(delegateQueue, ^{ @autoreleasepool {
					
					[theDelegate socket:self didWritePartialDataOfLength:bytesWritten tag:theWriteTag];
				}});
			}
		}
	}
	
	// Check for errors
	//如果有错，则报错断开连接
	if (error)
	{
		[self closeWithError:[self errnoErrorWithReason:@"Error in write() function"]];
	}
	
	// Do not add any code here without first adding a return statement in the error case above.
}

//完成了当前的写
- (void)completeCurrentWrite
{
	LogTrace();
	
	NSAssert(currentWrite, @"Trying to complete current write when there is no current write.");
	

	__strong id theDelegate = delegate;
	
	if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didWriteDataWithTag:)])
	{
		long theWriteTag = currentWrite->tag;
		
        //调用完成写的回调
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			[theDelegate socket:self didWriteDataWithTag:theWriteTag];
		}});
	}
	
    //关闭当前写
	[self endCurrentWrite];
}

//和下面的读基本一样
- (void)endCurrentWrite
{
    //取消写超时
	if (writeTimer)
	{
		dispatch_source_cancel(writeTimer);
		writeTimer = NULL;
	}
	//清空当前写包
	currentWrite = nil;
}

//一样
- (void)setupWriteTimerWithTimeout:(NSTimeInterval)timeout
{
	if (timeout >= 0.0)
	{
		writeTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, socketQueue);
		
		__weak GCDAsyncSocket *weakSelf = self;
		
		dispatch_source_set_event_handler(writeTimer, ^{ @autoreleasepool {
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			__strong GCDAsyncSocket *strongSelf = weakSelf;
			if (strongSelf == nil) return_from_block;
			
            //做写超时的操作
			[strongSelf doWriteTimeout];
			
		#pragma clang diagnostic pop
		}});
		
		#if !OS_OBJECT_USE_OBJC
		dispatch_source_t theWriteTimer = writeTimer;
		dispatch_source_set_cancel_handler(writeTimer, ^{
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			LogVerbose(@"dispatch_release(writeTimer)");
			dispatch_release(theWriteTimer);
			
		#pragma clang diagnostic pop
		});
		#endif
		
		dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC));
		
		dispatch_source_set_timer(writeTimer, tt, DISPATCH_TIME_FOREVER, 0);
		dispatch_resume(writeTimer);
	}
}

- (void)doWriteTimeout
{
	// This is a little bit tricky.
	// Ideally we'd like to synchronously query the delegate about a timeout extension.
	// But if we do so synchronously we risk a possible deadlock.
	// So instead we have to do so asynchronously, and callback to ourselves from within the delegate block.
	
	flags |= kWritesPaused;
	
	__strong id theDelegate = delegate;

    //也是判断有没有写超时延时的代理
	if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:shouldTimeoutWriteWithTag:elapsed:bytesDone:)])
	{
		GCDAsyncWritePacket *theWrite = currentWrite;
		
		dispatch_async(delegateQueue, ^{ @autoreleasepool {
			
			NSTimeInterval timeoutExtension = 0.0;
			
			timeoutExtension = [theDelegate socket:self shouldTimeoutWriteWithTag:theWrite->tag
			                                                              elapsed:theWrite->timeout
			                                                            bytesDone:theWrite->bytesDone];
			
			dispatch_async(socketQueue, ^{ @autoreleasepool {
				
				[self doWriteTimeoutWithExtension:timeoutExtension];
			}});
		}});
	}
	else
	{
		[self doWriteTimeoutWithExtension:0.0];
	}
}
//写超时延时的方法
- (void)doWriteTimeoutWithExtension:(NSTimeInterval)timeoutExtension
{
	if (currentWrite)
	{
		if (timeoutExtension > 0.0)
		{
			currentWrite->timeout += timeoutExtension;
			
			// Reschedule the timer
			dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeoutExtension * NSEC_PER_SEC));
			dispatch_source_set_timer(writeTimer, tt, DISPATCH_TIME_FOREVER, 0);
			
			// Unpause writes, and continue
            //移除停止读
			flags &= ~kWritesPaused;
            //开始写
			[self doWriteData];
		}
		else
		{
			LogVerbose(@"WriteTimeout");
			
			[self closeWithError:[self writeTimeoutError]];
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//开启TLS
- (void)startTLS:(NSDictionary *)tlsSettings
{
	LogTrace();
	
	if (tlsSettings == nil)
    {
        // Passing nil/NULL to CFReadStreamSetProperty will appear to work the same as passing an empty dictionary,
        // but causes problems if we later try to fetch the remote host's certificate.
        // 
        // To be exact, it causes the following to return NULL instead of the normal result:
        // CFReadStreamCopyProperty(readStream, kCFStreamPropertySSLPeerCertificates)
        // 
        // So we use an empty dictionary instead, which works perfectly.
        
        tlsSettings = [NSDictionary dictionary];
    }
	//新生成一个TLS特殊的包
	GCDAsyncSpecialPacket *packet = [[GCDAsyncSpecialPacket alloc] initWithTLSSettings:tlsSettings];
	
    
	dispatch_async(socketQueue, ^{ @autoreleasepool {
		
		if ((flags & kSocketStarted) && !(flags & kQueuedTLS) && !(flags & kForbidReadsWrites))
		{
            //添加到读写Queue中去
			[readQueue addObject:packet];
			[writeQueue addObject:packet];
			//把TLS标记加上
			flags |= kQueuedTLS;
			//开始读取TLS的任务，读到这个包会做TLS认证。在这之前的包还是不用认证就可以传送完
			[self maybeDequeueRead];
			[self maybeDequeueWrite];
		}
	}});
	
}
//可能开启TLS
- (void)maybeStartTLS
{
	// We can't start TLS until:
	// - All queued reads prior to the user calling startTLS are complete
	// - All queued writes prior to the user calling startTLS are complete
	// 
	// We'll know these conditions are met when both kStartingReadTLS and kStartingWriteTLS are set
	
    //只有读和写TLS都开启
	if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
	{
        //需要安全传输
		BOOL useSecureTransport = YES;
		
		#if TARGET_OS_IPHONE
		{
            //拿到当前读的数据
			GCDAsyncSpecialPacket *tlsPacket = (GCDAsyncSpecialPacket *)currentRead;
            //得到设置字典
			NSDictionary *tlsSettings = tlsPacket->tlsSettings;
			
            //拿到Key为CFStreamTLS的 value
			NSNumber *value = [tlsSettings objectForKey:GCDAsyncSocketUseCFStreamForTLS];
            
			if (value && [value boolValue])
                //如果是用CFStream的，则安全传输为NO
				useSecureTransport = NO;
		}
		#endif
		//如果使用安全通道
		if (useSecureTransport)
		{
            //开启TLS
			[self ssl_startTLS];
		}
        //CFStream形式的Tls
		else
		{
		#if TARGET_OS_IPHONE
			[self cf_startTLS];
		#endif
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security via SecureTransport
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//SSL读取数据最终方法
- (OSStatus)sslReadWithBuffer:(void *)buffer length:(size_t *)bufferLength
{
    
	LogVerbose(@"sslReadWithBuffer:%p length:%lu", buffer, (unsigned long)*bufferLength);
	
    //如果当前socket未读取数据为0,且sslPreBuffer中可用的字节为0，说明无数据可读，恢复source，等待之后的数据触发
	if ((socketFDBytesAvailable == 0) && ([sslPreBuffer availableBytes] == 0))
	{
		LogVerbose(@"%@ - No data available to read...", THIS_METHOD);
		
		// No data available to read.
		// 
		// Need to wait for readSource to fire and notify us of
		// available data in the socket's internal read buffer.
		//恢复读source
		[self resumeReadSource];
		//把buffer的长度设置为0
		*bufferLength = 0;
        //返回IO阻塞的错误，即当前没数据
		return errSSLWouldBlock;
	}
	
    //开始读数据
	size_t totalBytesRead = 0;
	size_t totalBytesLeftToBeRead = *bufferLength;
	
	BOOL done = NO;
	BOOL socketError = NO;
	
	// 
	// STEP 1 : READ FROM SSL PRE BUFFER
	// 
	
    //拿到sslBuffer的未读数据长度
	size_t sslPreBufferLength = [sslPreBuffer availableBytes];
	
	if (sslPreBufferLength > 0)
	{
		LogVerbose(@"%@: Reading from SSL pre buffer...", THIS_METHOD);
		
		size_t bytesToCopy;
        //如果这个长度大于这次给的数据长度，复制的永远要短的那个
		if (sslPreBufferLength > totalBytesLeftToBeRead)
            //等于给的长度
			bytesToCopy = totalBytesLeftToBeRead;
		else
            //等于实际长度
			bytesToCopy = sslPreBufferLength;
		
		LogVerbose(@"%@: Copying %zu bytes from sslPreBuffer", THIS_METHOD, bytesToCopy);
		
        //将sslPreBuffer中的数据写到buffer中
		memcpy(buffer, [sslPreBuffer readBuffer], bytesToCopy);
		[sslPreBuffer didRead:bytesToCopy];
		
		LogVerbose(@"%@: sslPreBuffer.length = %zu", THIS_METHOD, [sslPreBuffer availableBytes]);
		
        //已读数据加上
		totalBytesRead += bytesToCopy;
        //需要读的数据减去
		totalBytesLeftToBeRead -= bytesToCopy;
		
        //如果需要读的数据 = 0 则done为YES
		done = (totalBytesLeftToBeRead == 0);
		
		if (done) LogVerbose(@"%@: Complete", THIS_METHOD);
	}
	
	// 
	// STEP 2 : READ FROM SOCKET
	// 
	
    //没完成而且socket中有数据可读，则再去SOCKET中去读
	if (!done && (socketFDBytesAvailable > 0))
	{
		LogVerbose(@"%@: Reading from socket...", THIS_METHOD);
		
        //拿到socket
		int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
		
		BOOL readIntoPreBuffer;
		size_t bytesToRead;
		uint8_t *buf;
		
        //如果socket中可读的数据大于需要读的，始终用大的
		if (socketFDBytesAvailable > totalBytesLeftToBeRead)
		{
			// Read all available data from socket into sslPreBuffer.
			// Then copy requested amount into dataBuffer.
			
			LogVerbose(@"%@: Reading into sslPreBuffer...", THIS_METHOD);
			
			[sslPreBuffer ensureCapacityForWrite:socketFDBytesAvailable];
			
            //标识可以写到prebuffer中去，因为这个包数据完了
			readIntoPreBuffer = YES;
            //要读的数据写为socket可读数据大小
			bytesToRead = (size_t)socketFDBytesAvailable;
            
            //拿到起点指针，sslPrebuffer
			buf = [sslPreBuffer writeBuffer];
		}
		else
		{
			// Read available data from socket directly into dataBuffer.
			
			LogVerbose(@"%@: Reading directly into dataBuffer...", THIS_METHOD);
			
            //则不写到prebuffer中去，因为这个包数据还没读完
			readIntoPreBuffer = NO;
			bytesToRead = totalBytesLeftToBeRead;
            //直接把数据写到传过来的参数buffer中去
			buf = (uint8_t *)buffer + totalBytesRead;
		}
		
        //去socket中去读，长度为 bytesToRead，写到buf中去
		ssize_t result = read(socketFD, buf, bytesToRead);
		LogVerbose(@"%@: read from socket = %zd", THIS_METHOD, result);
		
        //错误
		if (result < 0)
		{
			LogVerbose(@"%@: read errno = %i", THIS_METHOD, errno);
			
			if (errno != EWOULDBLOCK)
			{
				socketError = YES;
			}
			
			socketFDBytesAvailable = 0;
		}
        //EOF 读取超出文件
		else if (result == 0)
		{
			LogVerbose(@"%@: read EOF", THIS_METHOD);
			
			socketError = YES;
			socketFDBytesAvailable = 0;
		}
        //正常
		else
		{
            //读取到的大小
			size_t bytesReadFromSocket = result;
			//socket中可读大小大于读到的大小
			if (socketFDBytesAvailable > bytesReadFromSocket)
                //减去
				socketFDBytesAvailable -= bytesReadFromSocket;
			else
				socketFDBytesAvailable = 0;
			
            //socket中比需要读的数据多，说明这个包的数据读完了，则直接把数据移到prebuffer中去
			if (readIntoPreBuffer)
			{
                
				[sslPreBuffer didWrite:bytesReadFromSocket];
				
                //拿到小的
				size_t bytesToCopy = MIN(totalBytesLeftToBeRead, bytesReadFromSocket);
				
				LogVerbose(@"%@: Copying %zu bytes out of sslPreBuffer", THIS_METHOD, bytesToCopy);
				
                //把数据从 sslPreBuffer 移到buffer中
				memcpy((uint8_t *)buffer + totalBytesRead, [sslPreBuffer readBuffer], bytesToCopy);
                //移动已读指针
				[sslPreBuffer didRead:bytesToCopy];
				
                //给已读加上复制的这部分
				totalBytesRead += bytesToCopy;
                //给剩余需要读的减去这部分
				totalBytesLeftToBeRead -= bytesToCopy;
				
				LogVerbose(@"%@: sslPreBuffer.length = %zu", THIS_METHOD, [sslPreBuffer availableBytes]);
			}
            //加上这部分数据仍旧没有读完，则暂不处理（数据已经在传过来的buffer参数中去了，sslPreBuffer中没有数据）
			else
			{
                //已读加上从socket中读取的这部分
				totalBytesRead += bytesReadFromSocket;
				totalBytesLeftToBeRead -= bytesReadFromSocket;
			}
			
            //判断当前包是否读完
			done = (totalBytesLeftToBeRead == 0);
			
			if (done) LogVerbose(@"%@: Complete", THIS_METHOD);
		}
	}
	
	*bufferLength = totalBytesRead;
	
	if (done)
		return noErr;
	
	if (socketError)
		return errSSLClosedAbort;
	
    //没读完数据，则返回I/O阻塞
	return errSSLWouldBlock;
}

- (OSStatus)sslWriteWithBuffer:(const void *)buffer length:(size_t *)bufferLength
{
    //如果当前socket不接受写
	if (!(flags & kSocketCanAcceptBytes))
	{
		// Unable to write.
		// 
		// Need to wait for writeSource to fire and notify us of
		// available space in the socket's internal write buffer.
		//恢复source
		[self resumeWriteSource];
		
		*bufferLength = 0;
        //报I/O阻塞错误
		return errSSLWouldBlock;
	}
	
    //拿到需要写的长度
	size_t bytesToWrite = *bufferLength;
	size_t bytesWritten = 0;
	
	BOOL done = NO;
	BOOL socketError = NO;
	
	int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
	//调用write去写
	ssize_t result = write(socketFD, buffer, bytesToWrite);
	
	if (result < 0)
	{
		if (errno != EWOULDBLOCK)
		{
			socketError = YES;
		}
		//当前写失败了，标记为不可写状态
		flags &= ~kSocketCanAcceptBytes;
	}
    
    //写到边界，没写完
	else if (result == 0)
	{
		flags &= ~kSocketCanAcceptBytes;
	}
    
    //正常写
	else
	{
        //拿到写的长度
		bytesWritten = result;
		//判断是否写完
		done = (bytesWritten == bytesToWrite);
	}
    
	//把本次写的长度返回出去
	*bufferLength = bytesWritten;
	//写完返回没错
	if (done)
		return noErr;
	
	if (socketError)
		return errSSLClosedAbort;
	
    //走到这说明没写完，返回I/O阻塞错误
	return errSSLWouldBlock;
}

//读函数
static OSStatus SSLReadFunction(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    //拿到socket
	GCDAsyncSocket *asyncSocket = (__bridge GCDAsyncSocket *)connection;
	
    //断言当前为socketQueue
	NSCAssert(dispatch_get_specific(asyncSocket->IsOnSocketQueueOrTargetQueueKey), @"What the deuce?");
	
    //读取数据，并且返回状态码
	return [asyncSocket sslReadWithBuffer:data length:dataLength];
}

//写函数
static OSStatus SSLWriteFunction(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
	GCDAsyncSocket *asyncSocket = (__bridge GCDAsyncSocket *)connection;
	
	NSCAssert(dispatch_get_specific(asyncSocket->IsOnSocketQueueOrTargetQueueKey), @"What the deuce?");
	
	return [asyncSocket sslWriteWithBuffer:data length:dataLength];
}

//开启TLS，这个方法主要是建立TLS连接，并且配置SSL上下文对象sslContext，为TLS握手做准备
- (void)ssl_startTLS
{
	LogTrace();
	
	LogVerbose(@"Starting TLS (via SecureTransport)...");
	
    //状态标记
	OSStatus status;
	
    //拿到当前读的数据包
	GCDAsyncSpecialPacket *tlsPacket = (GCDAsyncSpecialPacket *)currentRead;
	if (tlsPacket == nil) // Code to quiet the analyzer
	{
		NSAssert(NO, @"Logic error");
		
		[self closeWithError:[self otherError:@"Logic error"]];
		return;
	}
    //拿到设置
	NSDictionary *tlsSettings = tlsPacket->tlsSettings;
	
	// Create SSLContext, and setup IO callbacks and connection ref
	
    //根据key来判断，当前包是否是服务端的
	BOOL isServer = [[tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLIsServer] boolValue];
	
    //创建SSL上下文
	#if TARGET_OS_IPHONE || (__MAC_OS_X_VERSION_MIN_REQUIRED >= 1080)
	{
        //如果是服务端的创建服务端上下文，否则是客户端的上下文，用stream形式
		if (isServer)
			sslContext = SSLCreateContext(kCFAllocatorDefault, kSSLServerSide, kSSLStreamType);
		else
			sslContext = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
		//为空则报错返回
		if (sslContext == NULL)
		{
			[self closeWithError:[self otherError:@"Error in SSLCreateContext"]];
			return;
		}
	}
    
	#else // (__MAC_OS_X_VERSION_MIN_REQUIRED < 1080)
	{
		status = SSLNewContext(isServer, &sslContext);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLNewContext"]];
			return;
		}
	}
	#endif
	
    //给SSL上下文设置 IO回调 分别为SSL 读写函数
	status = SSLSetIOFuncs(sslContext, &SSLReadFunction, &SSLWriteFunction);
    //设置出错
	if (status != noErr)
	{
		[self closeWithError:[self otherError:@"Error in SSLSetIOFuncs"]];
		return;
	}
    
	//在握手之调用，建立SSL连接 ,第一次连接 1
	status = SSLSetConnection(sslContext, (__bridge SSLConnectionRef)self);
    //连接出错
	if (status != noErr)
	{
		[self closeWithError:[self otherError:@"Error in SSLSetConnection"]];
		return;
	}

    //是否应该手动的去信任SSL
	BOOL shouldManuallyEvaluateTrust = [[tlsSettings objectForKey:GCDAsyncSocketManuallyEvaluateTrust] boolValue];
    //如果需要手动去信任
	if (shouldManuallyEvaluateTrust)
	{
        //是服务端的话，不需要，报错返回
		if (isServer)
		{
			[self closeWithError:[self otherError:@"Manual trust validation is not supported for server sockets"]];
			return;
		}
		//第二次连接 再去连接用kSSLSessionOptionBreakOnServerAuth的方式，去连接一次，这种方式可以直接信任服务端证书
		status = SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
        //错误直接返回
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetSessionOption"]];
			return;
		}
		
		#if !TARGET_OS_IPHONE && (__MAC_OS_X_VERSION_MIN_REQUIRED < 1080)
		
		// Note from Apple's documentation:
		//
		// It is only necessary to call SSLSetEnableCertVerify on the Mac prior to OS X 10.8.
		// On OS X 10.8 and later setting kSSLSessionOptionBreakOnServerAuth always disables the
		// built-in trust evaluation. All versions of iOS behave like OS X 10.8 and thus
		// SSLSetEnableCertVerify is not available on that platform at all.
        
		//为了防止kSSLSessionOptionBreakOnServerAuth这种情况下，产生了不受信任的环境
		status = SSLSetEnableCertVerify(sslContext, NO);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetEnableCertVerify"]];
			return;
		}
		
		#endif
	}

    //配置SSL上下文的设置
	// Configure SSLContext from given settings
	// 
	// Checklist:
	//  1. kCFStreamSSLPeerName
	//  2. kCFStreamSSLCertificates
	//  3. GCDAsyncSocketSSLPeerID
	//  4. GCDAsyncSocketSSLProtocolVersionMin
	//  5. GCDAsyncSocketSSLProtocolVersionMax
	//  6. GCDAsyncSocketSSLSessionOptionFalseStart
	//  7. GCDAsyncSocketSSLSessionOptionSendOneByteRecord
	//  8. GCDAsyncSocketSSLCipherSuites
	//  9. GCDAsyncSocketSSLDiffieHellmanParameters (Mac)
	//
	// Deprecated (throw error):
	// 10. kCFStreamSSLAllowsAnyRoot
	// 11. kCFStreamSSLAllowsExpiredRoots
	// 12. kCFStreamSSLAllowsExpiredCertificates
	// 13. kCFStreamSSLValidatesCertificateChain
	// 14. kCFStreamSSLLevel
	
	id value;
	
    //这个参数是用来获取证书名验证，如果设置为NULL，则不验证
	// 1. kCFStreamSSLPeerName
	
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLPeerName];
	if ([value isKindOfClass:[NSString class]])
	{
		NSString *peerName = (NSString *)value;
		
		const char *peer = [peerName UTF8String];
		size_t peerLen = strlen(peer);
		
        //把证书名设置给SSL
		status = SSLSetPeerDomainName(sslContext, peer, peerLen);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetPeerDomainName"]];
			return;
		}
	}
    //不是string就错误返回
	else if (value)
	{
        //这个断言啥用也没有啊。。
		NSAssert(NO, @"Invalid value for kCFStreamSSLPeerName. Value must be of type NSString.");
		
		[self closeWithError:[self otherError:@"Invalid value for kCFStreamSSLPeerName."]];
		return;
	}
	
    //用来获取到证书
	// 2. kCFStreamSSLCertificates
	
    //得到的是证书数组
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLCertificates];
	if ([value isKindOfClass:[NSArray class]])
	{
		CFArrayRef certs = (__bridge CFArrayRef)value;
		//设置证书数组给SSL上下文
		status = SSLSetCertificate(sslContext, certs);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetCertificate"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for kCFStreamSSLCertificates. Value must be of type NSArray.");
		
		[self closeWithError:[self otherError:@"Invalid value for kCFStreamSSLCertificates."]];
		return;
	}
	
	// 3. GCDAsyncSocketSSLPeerID
	//证书ID？？
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLPeerID];
	if ([value isKindOfClass:[NSData class]])
	{
		NSData *peerIdData = (NSData *)value;
		
		status = SSLSetPeerID(sslContext, [peerIdData bytes], [peerIdData length]);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetPeerID"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLPeerID. Value must be of type NSData."
		             @" (You can convert strings to data using a method like"
		             @" [string dataUsingEncoding:NSUTF8StringEncoding])");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLPeerID."]];
		return;
	}
	
	// 4. GCDAsyncSocketSSLProtocolVersionMin
	//SSL最低版本
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLProtocolVersionMin];
	if ([value isKindOfClass:[NSNumber class]])
	{
		SSLProtocol minProtocol = (SSLProtocol)[(NSNumber *)value intValue];
		if (minProtocol != kSSLProtocolUnknown)
		{
			status = SSLSetProtocolVersionMin(sslContext, minProtocol);
			if (status != noErr)
			{
				[self closeWithError:[self otherError:@"Error in SSLSetProtocolVersionMin"]];
				return;
			}
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLProtocolVersionMin. Value must be of type NSNumber.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLProtocolVersionMin."]];
		return;
	}
	
	// 5. GCDAsyncSocketSSLProtocolVersionMax
	//SSL最高版本
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLProtocolVersionMax];
	if ([value isKindOfClass:[NSNumber class]])
	{
		SSLProtocol maxProtocol = (SSLProtocol)[(NSNumber *)value intValue];
		if (maxProtocol != kSSLProtocolUnknown)
		{
			status = SSLSetProtocolVersionMax(sslContext, maxProtocol);
			if (status != noErr)
			{
				[self closeWithError:[self otherError:@"Error in SSLSetProtocolVersionMax"]];
				return;
			}
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLProtocolVersionMax. Value must be of type NSNumber.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLProtocolVersionMax."]];
		return;
	}
	
	// 6. GCDAsyncSocketSSLSessionOptionFalseStart
	//可选项 错误开始是啥？？
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLSessionOptionFalseStart];
	if ([value isKindOfClass:[NSNumber class]])
	{
		status = SSLSetSessionOption(sslContext, kSSLSessionOptionFalseStart, [value boolValue]);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetSessionOption (kSSLSessionOptionFalseStart)"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLSessionOptionFalseStart. Value must be of type NSNumber.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLSessionOptionFalseStart."]];
		return;
	}
	
	// 7. GCDAsyncSocketSSLSessionOptionSendOneByteRecord
	//发送一个字节记录？？
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLSessionOptionSendOneByteRecord];
	if ([value isKindOfClass:[NSNumber class]])
	{
		status = SSLSetSessionOption(sslContext, kSSLSessionOptionSendOneByteRecord, [value boolValue]);
		if (status != noErr)
		{
			[self closeWithError:
			  [self otherError:@"Error in SSLSetSessionOption (kSSLSessionOptionSendOneByteRecord)"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLSessionOptionSendOneByteRecord."
		             @" Value must be of type NSNumber.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLSessionOptionSendOneByteRecord."]];
		return;
	}
	
	// 8. GCDAsyncSocketSSLCipherSuites
	//wtf?
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLCipherSuites];
	if ([value isKindOfClass:[NSArray class]])
	{
		NSArray *cipherSuites = (NSArray *)value;
		NSUInteger numberCiphers = [cipherSuites count];
		SSLCipherSuite ciphers[numberCiphers];
		
		NSUInteger cipherIndex;
		for (cipherIndex = 0; cipherIndex < numberCiphers; cipherIndex++)
		{
			NSNumber *cipherObject = [cipherSuites objectAtIndex:cipherIndex];
			ciphers[cipherIndex] = [cipherObject shortValue];
		}
		
		status = SSLSetEnabledCiphers(sslContext, ciphers, numberCiphers);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetEnabledCiphers"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLCipherSuites. Value must be of type NSArray.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLCipherSuites."]];
		return;
	}
	
	// 9. GCDAsyncSocketSSLDiffieHellmanParameters
	
	#if !TARGET_OS_IPHONE
	value = [tlsSettings objectForKey:GCDAsyncSocketSSLDiffieHellmanParameters];
	if ([value isKindOfClass:[NSData class]])
	{
		NSData *diffieHellmanData = (NSData *)value;
		
		status = SSLSetDiffieHellmanParams(sslContext, [diffieHellmanData bytes], [diffieHellmanData length]);
		if (status != noErr)
		{
			[self closeWithError:[self otherError:@"Error in SSLSetDiffieHellmanParams"]];
			return;
		}
	}
	else if (value)
	{
		NSAssert(NO, @"Invalid value for GCDAsyncSocketSSLDiffieHellmanParameters. Value must be of type NSData.");
		
		[self closeWithError:[self otherError:@"Invalid value for GCDAsyncSocketSSLDiffieHellmanParameters."]];
		return;
	}
	#endif
	
	// DEPRECATED checks 弃用的检查，如果有下列value，则都报弃用的错误
	
	// 10. kCFStreamSSLAllowsAnyRoot
	//允许任何根地址？
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsAnyRoot];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsAnyRoot"
		             @" - You must use manual trust evaluation");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsAnyRoot"]];
		return;
	}
	
	// 11. kCFStreamSSLAllowsExpiredRoots
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsExpiredRoots];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsExpiredRoots"
		             @" - You must use manual trust evaluation");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsExpiredRoots"]];
		return;
	}
	
	// 12. kCFStreamSSLValidatesCertificateChain
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLValidatesCertificateChain];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLValidatesCertificateChain"
		             @" - You must use manual trust evaluation");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLValidatesCertificateChain"]];
		return;
	}
	
	// 13. kCFStreamSSLAllowsExpiredCertificates
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLAllowsExpiredCertificates];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLAllowsExpiredCertificates"
		             @" - You must use manual trust evaluation");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLAllowsExpiredCertificates"]];
		return;
	}
	
	// 14. kCFStreamSSLLevel
	
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	value = [tlsSettings objectForKey:(__bridge NSString *)kCFStreamSSLLevel];
	#pragma clang diagnostic pop
	if (value)
	{
		NSAssert(NO, @"Security option unavailable - kCFStreamSSLLevel"
		             @" - You must use GCDAsyncSocketSSLProtocolVersionMin & GCDAsyncSocketSSLProtocolVersionMax");
		
		[self closeWithError:[self otherError:@"Security option unavailable - kCFStreamSSLLevel"]];
		return;
	}
	
	// Setup the sslPreBuffer
	// 
	// Any data in the preBuffer needs to be moved into the sslPreBuffer,
	// as this data is now part of the secure read stream.
	
    //初始化SSL提前缓冲 也是4Kb
	sslPreBuffer = [[GCDAsyncSocketPreBuffer alloc] initWithCapacity:(1024 * 4)];
	//获取到preBuffer可读大小
	size_t preBufferLength  = [preBuffer availableBytes];
	
    //如果有可读内容
	if (preBufferLength > 0)
	{
        //确保SSL提前缓冲的大小
		[sslPreBuffer ensureCapacityForWrite:preBufferLength];
		//从readBuffer开始读，读这个长度到 SSL提前缓冲的writeBuffer中去
		memcpy([sslPreBuffer writeBuffer], [preBuffer readBuffer], preBufferLength);
        //移动提前的读buffer
		[preBuffer didRead:preBufferLength];
        //移动sslPreBuffer的写buffer
		[sslPreBuffer didWrite:preBufferLength];
	}
	//拿到上次错误的code,并且让上次错误code = 没错
	sslErrCode = lastSSLHandshakeError = noErr;
	
	// Start the SSL Handshake process
	//开始SSL握手过程
	[self ssl_continueSSLHandshake];
}

//SSL的握手
- (void)ssl_continueSSLHandshake
{
	LogTrace();
	
	// If the return value is noErr, the session is ready for normal secure communication.
    //如果返回为noErr，这个会话已经准备好了普通安全的通信
	// If the return value is errSSLWouldBlock, the SSLHandshake function must be called again.
    //如果返回的value为errSSLWouldBlock，握手方法必须再次调用
	// If the return value is errSSLServerAuthCompleted, we ask delegate if we should trust the
    //如果返回为errSSLServerAuthCompleted，如果我们要调用代理，我们需要相信服务器，然后再次调用握手，去恢复握手或者关闭连接。
	// server and then call SSLHandshake again to resume the handshake or close the connection
	// errSSLPeerBadCert SSL error.
	// Otherwise, the return value indicates an error code.
    //否则，返回的value表明了错误的code
    
	//用我们的SSL上下文对象去握手
	OSStatus status = SSLHandshake(sslContext);
    //拿到握手的结果，赋值给上次握手的结果
	lastSSLHandshakeError = status;
	
    //如果没错
	if (status == noErr)
	{
		LogVerbose(@"SSLHandshake complete");
		
        //把开始读写TLS，从标记中移除
		flags &= ~kStartingReadTLS;
		flags &= ~kStartingWriteTLS;
        
		//把Socket安全通道标记加上
		flags |=  kSocketSecure;
		
        //拿到代理
		__strong id theDelegate = delegate;

		if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidSecure:)])
		{
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
				//调用socket已经开启安全通道的代理方法
				[theDelegate socketDidSecure:self];
			}});
		}
		//停止读取
		[self endCurrentRead];
        //停止写
		[self endCurrentWrite];
		//开始下一次读写任务
		[self maybeDequeueRead];
		[self maybeDequeueWrite];
	}
    //如果是认证错误
	else if (status == errSSLPeerAuthCompleted)
	{
		LogVerbose(@"SSLHandshake peerAuthCompleted - awaiting delegate approval");
		
		__block SecTrustRef trust = NULL;
        //从sslContext拿到证书相关的细节
		status = SSLCopyPeerTrust(sslContext, &trust);
        //SSl证书赋值出错
		if (status != noErr)
		{
			[self closeWithError:[self sslError:status]];
			return;
		}
		
        //拿到状态值
		int aStateIndex = stateIndex;
        //socketQueue
		dispatch_queue_t theSocketQueue = socketQueue;
		
		__weak GCDAsyncSocket *weakSelf = self;
		
        //创建一个完成Block
		void (^comletionHandler)(BOOL) = ^(BOOL shouldTrust){ @autoreleasepool {
		#pragma clang diagnostic push
		#pragma clang diagnostic warning "-Wimplicit-retain-self"
			
			dispatch_async(theSocketQueue, ^{ @autoreleasepool {
				
				if (trust) {
					CFRelease(trust);
					trust = NULL;
				}
				
				__strong GCDAsyncSocket *strongSelf = weakSelf;
				if (strongSelf)
				{
					[strongSelf ssl_shouldTrustPeer:shouldTrust stateIndex:aStateIndex];
				}
			}});
			
		#pragma clang diagnostic pop
		}};
		
		__strong id theDelegate = delegate;
		
		if (delegateQueue && [theDelegate respondsToSelector:@selector(socket:didReceiveTrust:completionHandler:)])
		{
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
                
#pragma mark - 调用代理我们自己去https认证
				[theDelegate socket:self didReceiveTrust:trust completionHandler:comletionHandler];
			}});
		}
        //没实现代理直接报错关闭连接。
		else
		{
			if (trust) {
				CFRelease(trust);
				trust = NULL;
			}
			
			NSString *msg = @"GCDAsyncSocketManuallyEvaluateTrust specified in tlsSettings,"
			                @" but delegate doesn't implement socket:shouldTrustPeer:";
			
			[self closeWithError:[self otherError:msg]];
			return;
		}
	}
    
    //握手错误为 IO阻塞的
	else if (status == errSSLWouldBlock)
	{
		LogVerbose(@"SSLHandshake continues...");
		
		// Handshake continues...
		// 
		// This method will be called again from doReadData or doWriteData.
	}
	else
	{
        //其他错误直接关闭连接
		[self closeWithError:[self sslError:status]];
	}
}

//修改信息后再次进行SSL握手
- (void)ssl_shouldTrustPeer:(BOOL)shouldTrust stateIndex:(int)aStateIndex
{
	LogTrace();
	
	if (aStateIndex != stateIndex)
	{
		LogInfo(@"Ignoring ssl_shouldTrustPeer - invalid state (maybe disconnected)");
		
		// One of the following is true
		// - the socket was disconnected
		// - the startTLS operation timed out
		// - the completionHandler was already invoked once
		
		return;
	}
	
	// Increment stateIndex to ensure completionHandler can only be called once.
	stateIndex++;
	
	if (shouldTrust)
	{
        NSAssert(lastSSLHandshakeError == errSSLPeerAuthCompleted, @"ssl_shouldTrustPeer called when last error is %d and not errSSLPeerAuthCompleted", (int)lastSSLHandshakeError);
		[self ssl_continueSSLHandshake];
	}
	else
	{
        
		[self closeWithError:[self sslError:errSSLPeerBadCert]];
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Security via CFStream
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if TARGET_OS_IPHONE

//完成握手
- (void)cf_finishSSLHandshake
{
	LogTrace();
	
	if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
	{
        //去掉正在TLS的标记
		flags &= ~kStartingReadTLS;
		flags &= ~kStartingWriteTLS;
		
        //标记为安全socket
		flags |= kSocketSecure;
		
		__strong id theDelegate = delegate;

        //调用完成安全sokcet代理
		if (delegateQueue && [theDelegate respondsToSelector:@selector(socketDidSecure:)])
		{
			dispatch_async(delegateQueue, ^{ @autoreleasepool {
				
				[theDelegate socketDidSecure:self];
			}});
		}
		//关闭当前读写
		[self endCurrentRead];
		[self endCurrentWrite];
		
        //开始下一次的读写
		[self maybeDequeueRead];
		[self maybeDequeueWrite];
	}
}
//握手出错，关闭socket
- (void)cf_abortSSLHandshake:(NSError *)error
{
	LogTrace();
	
	if ((flags & kStartingReadTLS) && (flags & kStartingWriteTLS))
	{
		flags &= ~kStartingReadTLS;
		flags &= ~kStartingWriteTLS;
		
		[self closeWithError:error];
	}
}

//CF流形式的TLS
- (void)cf_startTLS
{
	LogTrace();
	
	LogVerbose(@"Starting TLS (via CFStream)...");
	
    //如果preBuffer的中可读数据大于0，错误关闭
	if ([preBuffer availableBytes] > 0)
	{
		NSString *msg = @"Invalid TLS transition. Handshake has already been read from socket.";
		
		[self closeWithError:[self otherError:msg]];
		return;
	}
	
    //挂起读写source
	[self suspendReadSource];
	[self suspendWriteSource];
	
    //把未读的数据大小置为0
	socketFDBytesAvailable = 0;
    //去掉下面两种flag
	flags &= ~kSocketCanAcceptBytes;
	flags &= ~kSecureSocketHasBytesAvailable;
	
    //标记为CFStream
	flags |=  kUsingCFStreamForTLS;
	
    //如果创建读写stream失败
	if (![self createReadAndWriteStream])
	{
		[self closeWithError:[self otherError:@"Error in CFStreamCreatePairWithSocket"]];
		return;
	}
	//注册回调，这回监听可读数据了！！
	if (![self registerForStreamCallbacksIncludingReadWrite:YES])
	{
		[self closeWithError:[self otherError:@"Error in CFStreamSetClient"]];
		return;
	}
	//添加runloop
	if (![self addStreamsToRunLoop])
	{
		[self closeWithError:[self otherError:@"Error in CFStreamScheduleWithRunLoop"]];
		return;
	}
	
	NSAssert([currentRead isKindOfClass:[GCDAsyncSpecialPacket class]], @"Invalid read packet for startTLS");
	NSAssert([currentWrite isKindOfClass:[GCDAsyncSpecialPacket class]], @"Invalid write packet for startTLS");
	
    //拿到当前包
	GCDAsyncSpecialPacket *tlsPacket = (GCDAsyncSpecialPacket *)currentRead;
    //拿到ssl配置
	CFDictionaryRef tlsSettings = (__bridge CFDictionaryRef)tlsPacket->tlsSettings;
	
	// Getting an error concerning kCFStreamPropertySSLSettings ?
	// You need to add the CFNetwork framework to your iOS application.
	
    //直接设置给读写stream
	BOOL r1 = CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, tlsSettings);
	BOOL r2 = CFWriteStreamSetProperty(writeStream, kCFStreamPropertySSLSettings, tlsSettings);
	
	// For some reason, starting around the time of iOS 4.3,
	// the first call to set the kCFStreamPropertySSLSettings will return true,
	// but the second will return false.
	// 
	// Order doesn't seem to matter.
	// So you could call CFReadStreamSetProperty and then CFWriteStreamSetProperty, or you could reverse the order.
	// Either way, the first call will return true, and the second returns false.
	// 
	// Interestingly, this doesn't seem to affect anything.
	// Which is not altogether unusual, as the documentation seems to suggest that (for many settings)
	// setting it on one side of the stream automatically sets it for the other side of the stream.
	// 
	// Although there isn't anything in the documentation to suggest that the second attempt would fail.
	// 
	// Furthermore, this only seems to affect streams that are negotiating a security upgrade.
	// In other words, the socket gets connected, there is some back-and-forth communication over the unsecure
	// connection, and then a startTLS is issued.
	// So this mostly affects newer protocols (XMPP, IMAP) as opposed to older protocols (HTTPS).
	
    //设置失败
	if (!r1 && !r2) // Yes, the && is correct - workaround for apple bug.
	{
		[self closeWithError:[self otherError:@"Error in CFStreamSetProperty"]];
		return;
	}
	
    //打开流
	if (![self openStreams])
	{
		[self closeWithError:[self otherError:@"Error in CFStreamOpen"]];
		return;
	}
	
	LogVerbose(@"Waiting for SSL Handshake to complete...");
}

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark CFStream
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if TARGET_OS_IPHONE

+ (void)ignore:(id)_
{}

//开始CFStream的线程
+ (void)startCFStreamThreadIfNeeded
{
	LogTrace();
	
	static dispatch_once_t predicate;
	dispatch_once(&predicate, ^{
		//初始化stream的持有数
		cfstreamThreadRetainCount = 0;
        //创建一条stream的串行queue
		cfstreamThreadSetupQueue = dispatch_queue_create("GCDAsyncSocket-CFStreamThreadSetup", DISPATCH_QUEUE_SERIAL);
	});
	
    //在streamQueue中
	dispatch_sync(cfstreamThreadSetupQueue, ^{ @autoreleasepool {
		
        //先++在判断是否 == 1
		if (++cfstreamThreadRetainCount == 1)
		{
            //创建新的线程线程
			cfstreamThread = [[NSThread alloc] initWithTarget:self
			                                         selector:@selector(cfstreamThread)
			                                           object:nil];
            //开启线程
			[cfstreamThread start];
		}
	}});
}

//停止stream线程
+ (void)stopCFStreamThreadIfNeeded
{
	LogTrace();
	
	// The creation of the cfstreamThread is relatively expensive.
	// So we'd like to keep it available for recycling.
	// However, there's a tradeoff here, because it shouldn't remain alive forever.
	// So what we're going to do is use a little delay before taking it down.
	// This way it can be reused properly in situations where multiple sockets are continually in flux.
	//创建线程相对昂贵，所以我们要保持它可重复利用。然而，这里有一个权衡，因为它不应该仍旧活着，所以我们用一个小的延迟，来关闭它。
    //这是一种方式，它能在多个socket不断变化的环境下被重复利用。
    
    //延迟时间
	int delayInSeconds = 30;
	dispatch_time_t when = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
	//延迟30秒执行
    dispatch_after(when, cfstreamThreadSetupQueue, ^{ @autoreleasepool {
	#pragma clang diagnostic push
	#pragma clang diagnostic warning "-Wimplicit-retain-self"
		//如果cfstreamThreadRetainCount的持有数为0，直接返回
		if (cfstreamThreadRetainCount == 0)
		{
			LogWarn(@"Logic error concerning cfstreamThread start / stop");
			return_from_block;
		}
		
        //--刚好等于0
		if (--cfstreamThreadRetainCount == 0)
		{
            //先cancel
			[cfstreamThread cancel]; // set isCancelled flag
			
			// wake up the thread
            //这个函数啥都没干？？为什么要这么做？
#pragma mark - why did this?
            [[self class] performSelector:@selector(ignore:)
                                 onThread:cfstreamThread
                               withObject:[NSNull null]
                            waitUntilDone:NO];
            
			cfstreamThread = nil;
		}
		
	#pragma clang diagnostic pop
	}});
}

//开辟一个新线程，用于stream的
+ (void)cfstreamThread { @autoreleasepool
{
    //设置线程名
	[[NSThread currentThread] setName:GCDAsyncSocketThreadName];
	
	LogInfo(@"CFStreamThread: Started");
	
	// We can't run the run loop unless it has an associated input source or a timer.
	// So we'll just create a timer that will never fire - unless the server runs for decades.
    //注册一个定时器，时间间隔很大。类似Port防止runloop直接退出
	[NSTimer scheduledTimerWithTimeInterval:[[NSDate distantFuture] timeIntervalSinceNow]
	                                 target:self
	                               selector:@selector(ignore:)
	                               userInfo:nil
	                                repeats:YES];
	//拿到当前的线程和runloop
	NSThread *currentThread = [NSThread currentThread];
	NSRunLoop *currentRunLoop = [NSRunLoop currentRunLoop];
	//判断线程是否取消
	BOOL isCancelled = [currentThread isCancelled];
	
    // while循环， 如果没取消，则开启runloop, （这种方式相当于用了NSThreadCacel来和runloop绑定取消）
	while (!isCancelled && [currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]])
	{
        //如果能读到这，说明runloop结束了，则循环因为！YES，也就跳出这个循环
		isCancelled = [currentThread isCancelled];
	}
	
    //输出CFStreamThread线程停掉了
	LogInfo(@"CFStreamThread: Stopped");
}}

//注册CFStream
+ (void)scheduleCFStreams:(GCDAsyncSocket *)asyncSocket
{
	LogTrace();
    
    //断言当前线程是cfstreamThread，不是则报错
	NSAssert([NSThread currentThread] == cfstreamThread, @"Invoked on wrong thread");
	
    //获取到runloop
	CFRunLoopRef runLoop = CFRunLoopGetCurrent();
	//如果有readStream
	if (asyncSocket->readStream)
        //注册readStream在runloop的kCFRunLoopDefaultMode上
		CFReadStreamScheduleWithRunLoop(asyncSocket->readStream, runLoop, kCFRunLoopDefaultMode);
	
    //一样
	if (asyncSocket->writeStream)
		CFWriteStreamScheduleWithRunLoop(asyncSocket->writeStream, runLoop, kCFRunLoopDefaultMode);
}

//取消注册stream
+ (void)unscheduleCFStreams:(GCDAsyncSocket *)asyncSocket
{
	LogTrace();
	NSAssert([NSThread currentThread] == cfstreamThread, @"Invoked on wrong thread");
	
	CFRunLoopRef runLoop = CFRunLoopGetCurrent();
	
	if (asyncSocket->readStream)
		CFReadStreamUnscheduleFromRunLoop(asyncSocket->readStream, runLoop, kCFRunLoopDefaultMode);
	
	if (asyncSocket->writeStream)
		CFWriteStreamUnscheduleFromRunLoop(asyncSocket->writeStream, runLoop, kCFRunLoopDefaultMode);
}

#pragma mark CFStream的回调

//读stream的回调
static void CFReadStreamCallback (CFReadStreamRef stream, CFStreamEventType type, void *pInfo)
{
    //得到触发回调的sokcet
	GCDAsyncSocket *asyncSocket = (__bridge GCDAsyncSocket *)pInfo;
	
	switch(type)
	{
        //如果是可读数据的回调
		case kCFStreamEventHasBytesAvailable:
		{
            //在socketQueue中调用
			dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
				
				LogCVerbose(@"CFReadStreamCallback - HasBytesAvailable");
				//如果不是同一个stream，直接返回
				if (asyncSocket->readStream != stream)
					return_from_block;
				
                //如果包含正在初始化TLS，就先去握手再说
				if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
				{
					// If we set kCFStreamPropertySSLSettings before we opened the streams, this might be a lie.
					// (A callback related to the tcp stream, but not to the SSL layer).
					
					if (CFReadStreamHasBytesAvailable(asyncSocket->readStream))
					{
						asyncSocket->flags |= kSecureSocketHasBytesAvailable;
						[asyncSocket cf_finishSSLHandshake];
					}
				}
                //去读取数据
				else
				{
					asyncSocket->flags |= kSecureSocketHasBytesAvailable;
					[asyncSocket doReadData];
				}
			}});
			
			break;
		}
            //这是错误的回调
		default:
		{
            //得到错误
			NSError *error = (__bridge_transfer  NSError *)CFReadStreamCopyError(stream);
			
            //到达流尾的错误
			if (error == nil && type == kCFStreamEventEndEncountered)
			{
				error = [asyncSocket connectionClosedError];
			}
			
			dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
				
				LogCVerbose(@"CFReadStreamCallback - Other");
				
				if (asyncSocket->readStream != stream)
					return_from_block;
				
                //如果当前是正在进行SSL认证
				if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
				{
                    //则关闭ssl，报错
					[asyncSocket cf_abortSSLHandshake:error];
				}
				else
				{
                    //直接关闭
					[asyncSocket closeWithError:error];
				}
			}});
			
			break;
		}
	}
	
}

//写的回调
static void CFWriteStreamCallback (CFWriteStreamRef stream, CFStreamEventType type, void *pInfo)
{
	GCDAsyncSocket *asyncSocket = (__bridge GCDAsyncSocket *)pInfo;
	
	switch(type)
	{
            
            //如果可写字节
		case kCFStreamEventCanAcceptBytes:
		{
			dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
				
				LogCVerbose(@"CFWriteStreamCallback - CanAcceptBytes");
				
				if (asyncSocket->writeStream != stream)
					return_from_block;
				
				if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
				{
					// If we set kCFStreamPropertySSLSettings before we opened the streams, this might be a lie.
					// (A callback related to the tcp stream, but not to the SSL layer).
					
                    //判断当前sokcet是否可以写数据，而不被阻塞
					if (CFWriteStreamCanAcceptBytes(asyncSocket->writeStream))
					{
						asyncSocket->flags |= kSocketCanAcceptBytes;
						[asyncSocket cf_finishSSLHandshake];
					}
				}
				else
				{
					asyncSocket->flags |= kSocketCanAcceptBytes;
					[asyncSocket doWriteData];
				}
			}});
			
			break;
		}
		default:
		{
			NSError *error = (__bridge_transfer NSError *)CFWriteStreamCopyError(stream);
			
			if (error == nil && type == kCFStreamEventEndEncountered)
			{
				error = [asyncSocket connectionClosedError];
			}
			
			dispatch_async(asyncSocket->socketQueue, ^{ @autoreleasepool {
				
				LogCVerbose(@"CFWriteStreamCallback - Other");
				
				if (asyncSocket->writeStream != stream)
					return_from_block;
				
				if ((asyncSocket->flags & kStartingReadTLS) && (asyncSocket->flags & kStartingWriteTLS))
				{
					[asyncSocket cf_abortSSLHandshake:error];
				}
				else
				{
					[asyncSocket closeWithError:error];
				}
			}});
			
			break;
		}
	}
	
}

//创建读写stream
- (BOOL)createReadAndWriteStream
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	
	//如果有一个有值，就返回
	if (readStream || writeStream)
	{
		// Streams already created
		return YES;
	}
	//拿到socket，首选是socket4FD，其次socket6FD，都没有才是socketUN，socketUN应该是Unix的socket结构体
	int socketFD = (socket4FD != SOCKET_NULL) ? socket4FD : (socket6FD != SOCKET_NULL) ? socket6FD : socketUN;
	
    //如果都为空，返回NO
	if (socketFD == SOCKET_NULL)
	{
		// Cannot create streams without a file descriptor
		return NO;
	}
	
    //如果非连接，返回NO
	if (![self isConnected])
	{
		// Cannot create streams until file descriptor is connected
		return NO;
	}
	
	LogVerbose(@"Creating read and write stream...");
	
#pragma mark - 绑定Socket和CFStream
    //下面的接口用于创建一对 socket stream，一个用于读取，一个用于写入：
	CFStreamCreatePairWithSocket(NULL, (CFSocketNativeHandle)socketFD, &readStream, &writeStream);
	
	// The kCFStreamPropertyShouldCloseNativeSocket property should be false by default (for our case).
	// But let's not take any chances.
    
    
	
    //读写stream都设置成不会随着绑定的socket一起close,release。 kCFBooleanFalse不一起，kCFBooleanTrue一起
	if (readStream)
		CFReadStreamSetProperty(readStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
	if (writeStream)
		CFWriteStreamSetProperty(writeStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanFalse);
	
    //如果有一个为空
	if ((readStream == NULL) || (writeStream == NULL))
	{
		LogWarn(@"Unable to create read and write stream...");
		
        //关闭对应的stream
		if (readStream)
		{
			CFReadStreamClose(readStream);
			CFRelease(readStream);
			readStream = NULL;
		}
		if (writeStream)
		{
			CFWriteStreamClose(writeStream);
			CFRelease(writeStream);
			writeStream = NULL;
		}
		//返回创建失败
		return NO;
	}
	//创建成功
	return YES;
}

//注册Stream的回调
- (BOOL)registerForStreamCallbacksIncludingReadWrite:(BOOL)includeReadWrite
{
	LogVerbose(@"%@ %@", THIS_METHOD, (includeReadWrite ? @"YES" : @"NO"));
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    //判断读写stream是不是都为空
	NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
	
    //客户端stream上下文对象
	streamContext.version = 0;
	streamContext.info = (__bridge void *)(self);
	streamContext.retain = nil;
	streamContext.release = nil;
	streamContext.copyDescription = nil;
    
//    The open has completed successfully.
//    The stream has bytes to be read.
//    The stream can accept bytes for writing.
//        An error has occurred on the stream.
//        The end of the stream has been reached.
	
    //设置一个CF的flag  两种，一种是错误发生的时候，一种是stream事件结束
	CFOptionFlags readStreamEvents = kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered ;
	//如果包含读写
    if (includeReadWrite)
        //仍然有Bytes要读的时候     The stream has bytes to be read.
		readStreamEvents |= kCFStreamEventHasBytesAvailable;
	
    //给读stream设置客户端，会在之前设置的那些标记下回调函数 CFReadStreamCallback。设置失败的话直接返回NO
	if (!CFReadStreamSetClient(readStream, readStreamEvents, &CFReadStreamCallback, &streamContext))
	{
		return NO;
	}
	
    //写的flag,也一样
	CFOptionFlags writeStreamEvents = kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered;
	if (includeReadWrite)
		writeStreamEvents |= kCFStreamEventCanAcceptBytes;
	
	if (!CFWriteStreamSetClient(writeStream, writeStreamEvents, &CFWriteStreamCallback, &streamContext))
	{
		return NO;
	}
	//走到最后说明读写都设置回调成功，返回YES
	return YES;
}

//把stream添加到runloop上
- (BOOL)addStreamsToRunLoop
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
	
    //判断flag里是否包含kAddedStreamsToRunLoop，没添加过则添加。
	if (!(flags & kAddedStreamsToRunLoop))
	{
		LogVerbose(@"Adding streams to runloop...");
		
        
		[[self class] startCFStreamThreadIfNeeded];
        //在开启的线程中去执行，阻塞式的
		[[self class] performSelector:@selector(scheduleCFStreams:)
		                     onThread:cfstreamThread
		                   withObject:self
		                waitUntilDone:YES];
		
        //添加标识
		flags |= kAddedStreamsToRunLoop;
	}
	
	return YES;
}

//从runloop上移除流
- (void)removeStreamsFromRunLoop
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
	NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
	
	if (flags & kAddedStreamsToRunLoop)
	{
		LogVerbose(@"Removing streams from runloop...");
		
		[[self class] performSelector:@selector(unscheduleCFStreams:)
		                     onThread:cfstreamThread
		                   withObject:self
		                waitUntilDone:YES];
        //停止Stream线程
		[[self class] stopCFStreamThreadIfNeeded];
		
        //按位取反，在取与,相当于flag中移除了 kAddedStreamsToRunLoop
		flags &= ~kAddedStreamsToRunLoop;
	}
}

//打开stream
- (BOOL)openStreams
{
	LogTrace();
	
	NSAssert(dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey), @"Must be dispatched on socketQueue");
    //断言读写stream都不会空
	NSAssert((readStream != NULL && writeStream != NULL), @"Read/Write stream is null");
	
    //返回stream的状态
    /*
     kCFStreamStatusNotOpen = 0,
     kCFStreamStatusOpening,  // open is in-progress
     kCFStreamStatusOpen,
     kCFStreamStatusReading,
     kCFStreamStatusWriting,
     kCFStreamStatusAtEnd,    // no further bytes can be read/written
     kCFStreamStatusClosed,
     kCFStreamStatusError
     */
	CFStreamStatus readStatus = CFReadStreamGetStatus(readStream);
	CFStreamStatus writeStatus = CFWriteStreamGetStatus(writeStream);
	
    //如果有任意一个没有开启
	if ((readStatus == kCFStreamStatusNotOpen) || (writeStatus == kCFStreamStatusNotOpen))
	{
		LogVerbose(@"Opening read and write stream...");
		
        //开启
		BOOL r1 = CFReadStreamOpen(readStream);
		BOOL r2 = CFWriteStreamOpen(writeStream);
		
        //有一个开启失败
		if (!r1 || !r2)
		{
			LogError(@"Error in CFStreamOpen");
			return NO;
		}
	}
	
	return YES;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Advanced
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * See header file for big discussion of this method.
**/
- (BOOL)autoDisconnectOnClosedReadStream
{
	// Note: YES means kAllowHalfDuplexConnection is OFF
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		return ((config & kAllowHalfDuplexConnection) == 0);
	}
	else
	{
		__block BOOL result;
		
		dispatch_sync(socketQueue, ^{
			result = ((config & kAllowHalfDuplexConnection) == 0);
		});
		
		return result;
	}
}

/**
 * See header file for big discussion of this method.
**/
//
- (void)setAutoDisconnectOnClosedReadStream:(BOOL)flag
{
	// Note: YES means kAllowHalfDuplexConnection is OFF
	
	dispatch_block_t block = ^{
		
		if (flag)
			config &= ~kAllowHalfDuplexConnection;
		else
			config |= kAllowHalfDuplexConnection;
	};
	
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_async(socketQueue, block);
}


/**
 * See header file for big discussion of this method.
**/
- (void)markSocketQueueTargetQueue:(dispatch_queue_t)socketNewTargetQueue
{
	void *nonNullUnusedPointer = (__bridge void *)self;
	dispatch_queue_set_specific(socketNewTargetQueue, IsOnSocketQueueOrTargetQueueKey, nonNullUnusedPointer, NULL);
}

/**
 * See header file for big discussion of this method.
**/
- (void)unmarkSocketQueueTargetQueue:(dispatch_queue_t)socketOldTargetQueue
{
	dispatch_queue_set_specific(socketOldTargetQueue, IsOnSocketQueueOrTargetQueueKey, NULL, NULL);
}

/**
 * See header file for big discussion of this method.
**/
- (void)performBlock:(dispatch_block_t)block
{
	if (dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
		block();
	else
		dispatch_sync(socketQueue, block);
}

/**
 * Questions? Have you read the header file?
**/
- (int)socketFD
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return SOCKET_NULL;
	}
	
	if (socket4FD != SOCKET_NULL)
		return socket4FD;
	else
		return socket6FD;
}

/**
 * Questions? Have you read the header file?
**/
- (int)socket4FD
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return SOCKET_NULL;
	}
	
	return socket4FD;
}

/**
 * Questions? Have you read the header file?
**/
- (int)socket6FD
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return SOCKET_NULL;
	}
	
	return socket6FD;
}

#if TARGET_OS_IPHONE

/**
 * Questions? Have you read the header file?
**/
- (CFReadStreamRef)readStream
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NULL;
	}
	
	if (readStream == NULL)
		[self createReadAndWriteStream];
	
	return readStream;
}

/**
 * Questions? Have you read the header file?
**/
- (CFWriteStreamRef)writeStream
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NULL;
	}
	
	if (writeStream == NULL)
		[self createReadAndWriteStream];
	
	return writeStream;
}

- (BOOL)enableBackgroundingOnSocketWithCaveat:(BOOL)caveat
{
	if (![self createReadAndWriteStream])
	{
		// Error occurred creating streams (perhaps socket isn't open)
		return NO;
	}
	
	BOOL r1, r2;
	
	LogVerbose(@"Enabling backgrouding on socket");
	
	r1 = CFReadStreamSetProperty(readStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);
	r2 = CFWriteStreamSetProperty(writeStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);
	
	if (!r1 || !r2)
	{
		return NO;
	}
	
	if (!caveat)
	{
		if (![self openStreams])
		{
			return NO;
		}
	}
	
	return YES;
}

/**
 * Questions? Have you read the header file?
**/
- (BOOL)enableBackgroundingOnSocket
{
	LogTrace();
	
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NO;
	}
	
	return [self enableBackgroundingOnSocketWithCaveat:NO];
}

- (BOOL)enableBackgroundingOnSocketWithCaveat // Deprecated in iOS 4.???
{
	// This method was created as a workaround for a bug in iOS.
	// Apple has since fixed this bug.
	// I'm not entirely sure which version of iOS they fixed it in...
	
	LogTrace();
	
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NO;
	}
	
	return [self enableBackgroundingOnSocketWithCaveat:YES];
}

#endif

- (SSLContextRef)sslContext
{
	if (!dispatch_get_specific(IsOnSocketQueueOrTargetQueueKey))
	{
		LogWarn(@"%@ - Method only available from within the context of a performBlock: invocation", THIS_METHOD);
		return NULL;
	}
	
	return sslContext;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Class Utilities
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//根据host、port
+ (NSMutableArray *)lookupHost:(NSString *)host port:(uint16_t)port error:(NSError **)errPtr
{
	LogTrace();
	
	NSMutableArray *addresses = nil;
	NSError *error = nil;
    
    //如果Host是这localhost或者loopback
	if ([host isEqualToString:@"localhost"] || [host isEqualToString:@"loopback"])
	{
		// Use LOOPBACK address
		struct sockaddr_in nativeAddr4;
		nativeAddr4.sin_len         = sizeof(struct sockaddr_in);
		nativeAddr4.sin_family      = AF_INET;
		nativeAddr4.sin_port        = htons(port);
		nativeAddr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        //占位置0
		memset(&(nativeAddr4.sin_zero), 0, sizeof(nativeAddr4.sin_zero));
		
        //ipv6
		struct sockaddr_in6 nativeAddr6;
		nativeAddr6.sin6_len        = sizeof(struct sockaddr_in6);
		nativeAddr6.sin6_family     = AF_INET6;
		nativeAddr6.sin6_port       = htons(port);
		nativeAddr6.sin6_flowinfo   = 0;
		nativeAddr6.sin6_addr       = in6addr_loopback;
		nativeAddr6.sin6_scope_id   = 0;
		
		// Wrap the native address structures
		
		NSData *address4 = [NSData dataWithBytes:&nativeAddr4 length:sizeof(nativeAddr4)];
		NSData *address6 = [NSData dataWithBytes:&nativeAddr6 length:sizeof(nativeAddr6)];
		
        //两个添加进数组
		addresses = [NSMutableArray arrayWithCapacity:2];
		[addresses addObject:address4];
		[addresses addObject:address6];
	}
	else
	{
        //拿到port String
		NSString *portStr = [NSString stringWithFormat:@"%hu", port];
		
//        struct addrinfo {
        
        //1.ai_flags指定了如何来处理地址和名字,可取值如下：
        //AI_PASSIVE套接字地址用来监听和绑定，AI_CANONNAME需要一个规范名，AI_NUMERICHOST以数字格式返回主机地址
//            int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST */
        /*
         2.地址族，可取值如下：
         AF_INET          2            IPv4
         AF_INET6        23            IPv6
         AF_UNSPEC        0            协议无关
         */
//            int	ai_family;	/* PF_xxx */
        
        /*
        3. 指定我套接字的类型
         SOCK_STREAM        1            流
         SOCK_DGRAM        2            数据报
         */
//            int	ai_socktype;	/* SOCK_xxx */
      
        //4.ai_protocol指定协议类型。可取的值取决于ai_address和ai_socktype的值
//            int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
        //5.下面二进制定制的长度
//            socklen_t ai_addrlen;	/* length of ai_addr */
        //6.规范名
//            char	*ai_canonname;	/* canonical name for hostname */
        //7.二进制地址
//            struct	sockaddr *ai_addr;	/* binary address */
        //下一个addrinfo指针
//            struct	addrinfo *ai_next;	/* next structure in linked list */
//        };
        
        //定义三个addrInfo  是一个sockaddr结构的链表而不是一个地址清单
        
		struct addrinfo hints, *res, *res0;
		
        //初始化为0
		memset(&hints, 0, sizeof(hints));
        
        //相当于 AF_UNSPEC ，返回的是适用于指定主机名和服务名且适合任何协议族的地址。
		hints.ai_family   = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		
        /*
        int getaddrinfo( const char *hostname, const char *service, const struct addrinfo *hints, struct addrinfo **result );
         //hostname:一个主机名或者地址串(IPv4的点分十进制串或者IPv6的16进制串)
         //service：服务名可以是十进制的端口号，也可以是已定义的服务名称，如ftp、http等
         //hints：可以是一个空指针，也可以是一个指向某个addrinfo结构体的指针，调用者在这个结构中填入关于期望返回的信息类型的暗示。举例来说：指定的服务既可支持TCP也可支持UDP，所以调用者可以把hints结构中的ai_socktype成员设置成SOCK_DGRAM使得返回的仅仅是适用于数据报套接口的信息。
         result：本函数通过result指针参数返回一个指向addrinfo结构体链表的指针。
         返回值：0——成功，非0——出错

         */

        //根据host port，去获取地址信息。
        //处理名字到地址以及服务到端口这两种转换,返回的是一个sockaddr结构的链表而不是一个地址清单。注意之前也有一个获取地址的，那个是获取本机的，这个才是获取任何地址，可以传参数的函数
        //hints是期望的数据格式，真正的数据在res0中被赋值
		int gai_error = getaddrinfo([host UTF8String], [portStr UTF8String], &hints, &res0);
		
        //出错
		if (gai_error)
		{   //获取到错误
			error = [self gaiError:gai_error];
		}
        //正确获取到addrInfo
		else
		{
            //
			NSUInteger capacity = 0;
            //遍历 res0
			for (res = res0; res; res = res->ai_next)
			{
                //如果有IPV4 IPV6的，capacity+1
				if (res->ai_family == AF_INET || res->ai_family == AF_INET6) {
					capacity++;
				}
			}
			//生成一个地址数组，数组为capacity大小
			addresses = [NSMutableArray arrayWithCapacity:capacity];
			
            //再去遍历，为什么不一次遍历完呢。。。？
			for (res = res0; res; res = res->ai_next)
			{
                //IPV4
				if (res->ai_family == AF_INET)
				{
					// Found IPv4 address.
					// Wrap the native address structure, and add to results.
					//加到数组中
					NSData *address4 = [NSData dataWithBytes:res->ai_addr length:res->ai_addrlen];
					[addresses addObject:address4];
				}
				else if (res->ai_family == AF_INET6)
				{
					// Fixes connection issues with IPv6
					// https://github.com/robbiehanson/CocoaAsyncSocket/issues/429#issuecomment-222477158
					
					// Found IPv6 address.
					// Wrap the native address structure, and add to results.
                    //强转
					struct sockaddr_in6 *sockaddr = (struct sockaddr_in6 *)res->ai_addr;
                    //拿到port
					in_port_t *portPtr = &sockaddr->sin6_port;
                    //如果Port为0
					if ((portPtr != NULL) && (*portPtr == 0)) {
                        //赋值，用传进来的port
					        *portPtr = htons(port);
					}
                    //添加到数组
					NSData *address6 = [NSData dataWithBytes:res->ai_addr length:res->ai_addrlen];
					[addresses addObject:address6];
				}
			}
            //对应getaddrinfo 释放内存
			freeaddrinfo(res0);
			
            //如果地址里一个没有，报错 EAI_FAIL：名字解析中不可恢复的失败
			if ([addresses count] == 0)
			{
				error = [self gaiError:EAI_FAIL];
			}
		}
	}
	//赋值错误
	if (errPtr) *errPtr = error;
    //返回地址
	return addresses;
}

//得到host
+ (NSString *)hostFromSockaddr4:(const struct sockaddr_in *)pSockaddr4
{
	char addrBuf[INET_ADDRSTRLEN];
	
    //可以在将IP地址在“点分十进制”和“二进制整数”之间转换。
    /*
     const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
     这个函数转换网络二进制结构到ASCII类型的地址，参数的作用和inet_pton相同，只是多了一个参数socklen_t cnt,他是所指向缓存区dst的大小，避免溢出，如果缓存区太小无法存储地址的值，则返回一个空指针，并将errno置为ENOSPC。

     */
    //去转换host
	if (inet_ntop(AF_INET, &pSockaddr4->sin_addr, addrBuf, (socklen_t)sizeof(addrBuf)) == NULL)
	{
        //转换失败，只存\0
		addrBuf[0] = '\0';
	}
	
    //返回host
	return [NSString stringWithCString:addrBuf encoding:NSASCIIStringEncoding];
}

//和上面一样
+ (NSString *)hostFromSockaddr6:(const struct sockaddr_in6 *)pSockaddr6
{
	char addrBuf[INET6_ADDRSTRLEN];
	
	if (inet_ntop(AF_INET6, &pSockaddr6->sin6_addr, addrBuf, (socklen_t)sizeof(addrBuf)) == NULL)
	{
		addrBuf[0] = '\0';
	}
	
	return [NSString stringWithCString:addrBuf encoding:NSASCIIStringEncoding];
}

//返回Port
+ (uint16_t)portFromSockaddr4:(const struct sockaddr_in *)pSockaddr4
{
    //ntohs 还是将网络字节顺序转换为主机字节序，16位方法 ntohl 32位
	return ntohs(pSockaddr4->sin_port);
}
//IPV6 Port
+ (uint16_t)portFromSockaddr6:(const struct sockaddr_in6 *)pSockaddr6
{
	return ntohs(pSockaddr6->sin6_port);
}

//从server端地址，获取到url
+ (NSURL *)urlFromSockaddrUN:(const struct sockaddr_un *)pSockaddr
{
	NSString *path = [NSString stringWithUTF8String:pSockaddr->sun_path];
	return [NSURL fileURLWithPath:path];
}

//得到host
+ (NSString *)hostFromAddress:(NSData *)address
{
	NSString *host;
	
	if ([self getHost:&host port:NULL fromAddress:address])
		return host;
	else
		return nil;
}

//从地址data中获取到Port
+ (uint16_t)portFromAddress:(NSData *)address
{
	uint16_t port;
	
	if ([self getHost:NULL port:&port fromAddress:address])
		return port;
	else
		return 0;
}

//判断IPV4
+ (BOOL)isIPv4Address:(NSData *)address
{
    //判断大于等于IPV4的长度
	if ([address length] >= sizeof(struct sockaddr))
	{
        
		const struct sockaddr *sockaddrX = [address bytes];
		//如果是AF_INET IPV4
		if (sockaddrX->sa_family == AF_INET) {
			return YES;
		}
	}
	
	return NO;
}

//判断IPV6
+ (BOOL)isIPv6Address:(NSData *)address
{
    //判断大于等于IPV4的长度
	if ([address length] >= sizeof(struct sockaddr))
	{
		const struct sockaddr *sockaddrX = [address bytes];
        //如果是AF_INET6 IPV6
		if (sockaddrX->sa_family == AF_INET6) {
			return YES;
		}
	}
	
	return NO;
}

//多获取Host
+ (BOOL)getHost:(NSString **)hostPtr port:(uint16_t *)portPtr fromAddress:(NSData *)address
{
	return [self getHost:hostPtr port:portPtr family:NULL fromAddress:address];
}

//多获取family
+ (BOOL)getHost:(NSString **)hostPtr port:(uint16_t *)portPtr family:(sa_family_t *)afPtr fromAddress:(NSData *)address
{
    
    //地址length大于 IPV4结构体的大小才继续
	if ([address length] >= sizeof(struct sockaddr))
	{
        //得到地址结构体
		const struct sockaddr *sockaddrX = [address bytes];
		//IPV4
		if (sockaddrX->sa_family == AF_INET)
		{
            //在判断一次？
			if ([address length] >= sizeof(struct sockaddr_in))
			{
				struct sockaddr_in sockaddr4;
                //copy一遍，为啥这么重复。。
				memcpy(&sockaddr4, sockaddrX, sizeof(sockaddr4));
				
                //赋值
				if (hostPtr) *hostPtr = [self hostFromSockaddr4:&sockaddr4];
				if (portPtr) *portPtr = [self portFromSockaddr4:&sockaddr4];
				if (afPtr)   *afPtr   = AF_INET;
				
				return YES;
			}
		}
        //IPV6
		else if (sockaddrX->sa_family == AF_INET6)
		{
			if ([address length] >= sizeof(struct sockaddr_in6))
			{
				struct sockaddr_in6 sockaddr6;
				memcpy(&sockaddr6, sockaddrX, sizeof(sockaddr6));
				
				if (hostPtr) *hostPtr = [self hostFromSockaddr6:&sockaddr6];
				if (portPtr) *portPtr = [self portFromSockaddr6:&sockaddr6];
				if (afPtr)   *afPtr   = AF_INET6;
				
				return YES;
			}
		}
	}
	
	return NO;
}

+ (NSData *)CRLFData
{
	return [NSData dataWithBytes:"\x0D\x0A" length:2];
}

+ (NSData *)CRData
{
	return [NSData dataWithBytes:"\x0D" length:1];
}

+ (NSData *)LFData
{
	return [NSData dataWithBytes:"\x0A" length:1];
}

+ (NSData *)ZeroData
{
	return [NSData dataWithBytes:"" length:1];
}

@end	
