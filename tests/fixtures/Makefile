CC = gcc
CFLAGS_EASY = -fno-stack-protector -no-pie -z execstack -z norelro
CFLAGS_MEDIUM = -fno-stack-protector -no-pie -z relro

all: stack_overflow stack_overflow_medium format_string

stack_overflow: stack_overflow.c
	$(CC) $(CFLAGS_EASY) -o $@ $<

stack_overflow_medium: stack_overflow.c
	$(CC) $(CFLAGS_MEDIUM) -o $@ $<

format_string: format_string.c
	$(CC) $(CFLAGS_MEDIUM) -o $@ $<

clean:
	rm -f stack_overflow stack_overflow_medium format_string
