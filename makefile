CPP = /usr/bin/g++
CC = /usr/bin/gcc
OBJ = WebRadioServer.o
LIBS = -L"/lib" -static-libgcc  -lSDL2 -lSDL2_mixer -lmp3lame -lssl -lcrypto -lpthread -lm
INCS = -I./ -I/usr/include -I/usr/include/SDL2 -Wmultichar -DHTTP_SSL
BIN = content/WebRadioServer
RM = /usr/bin/rm -f

.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $(BIN) $(LIBS)

WebRadioServer.o: WebRadioServer.cpp
	$(CC) -c WebRadioServer.cpp -o WebRadioServer.o $(INCS)
