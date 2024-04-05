# 定义编译器
CC=gcc

# 定义编译选项，包括所有警告、调试信息和优化级别
CFLAGS=-Wall -Wextra -g -O2

# 定义链接选项，这里可能需要添加pcap库和网络库
LFLAGS=-lpcap

# 定义目标文件
OBJS=packet_constructor.o tcp_synflood.o

# 定义最终目标：tcp_flood_test
tcp_flood_test: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LFLAGS)

# 定义编译规则
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

# 包含自动生成的依赖文件
-include $(OBJS:.o=.d)

# 生成依赖文件的规则
%.d: %.c
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@

# 定义'clean'规则，以便可以用'make clean'命令清理工程
clean:
	rm -f *.o *.d
# 伪目标声明，确保这些目标不会与文件名冲突
.PHONY: clean
