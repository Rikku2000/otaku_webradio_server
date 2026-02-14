#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <SDL.h>
#include <SDL_mixer.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"SDL2.lib")
#pragma comment(lib,"SDL2main.lib")
#pragma comment(lib,"SDL2_mixer.lib")
#pragma comment(lib,"libmp3lame.lib")
#define thread_return DWORD WINAPI
#define close_socket closesocket
#define snprintf _snprintf
#include <conio.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define thread_return void*
#define close_socket close
#include <unistd.h>
#include <fcntl.h>
#endif

#ifdef _WIN32
#include "lame.h"
#ifdef HTTP_SSL
#include <ssl.h>
#include <err.h>
#endif
#else
#include "lame/lame.h"
#ifdef HTTP_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#endif

#define BUFFER 2048
#define MAX_FILES 4096
#define MAX_CLIENT 1024
#define MP3_FRAME_SAMPLES 1152

#define RESET       "\033[0m"
#define RED         "\033[1;31m"
#define GREEN       "\033[1;32m"
#define BLUE        "\033[1;34m"
#define YELLOW      "\033[1;33m"
#define CYAN        "\033[1;36m"
#define WHITE       "\033[1;37m"

int shuffle = 1;
int shuffle_morning = -1, shuffle_afternoon = -1, shuffle_evening = -1, shuffle_night = -1, shuffle_weekend = -1;
int scan_interval = 60;
int fade_time = 2000;
int enable_scripts = 1;
int stream_port = 8010;
int status_port = 8011;
int enable_webui=1;
int webui_port=8081;
char webui_folder[BUFFER] = "player";
int enable_ssl = 0;
char ssl_cert_file[256] = "cert.pem";
char ssl_key_file[256]  = "key.pem";
#ifdef HTTP_SSL
SSL_CTX *ssl_ctx = NULL;
#endif
int max_clients = 32;
int client_buffer_kb = 128;
int client_timeout_sec = 10;
int ptt_enable = 1;
char ptt_key[16] = "SDLK_SPACE";
int ptt_volume = 80;
int music_duck = 50;
int stream_bitrate = 64;
int frame_pacing = 1;
char notification_mode[16] = "over";

char music_folder[BUFFER] = "music";
char notif_folder[BUFFER] = "notifications";
char morning[BUFFER] = "music/morning";
char afternoon[BUFFER] = "music/afternoon";
char evening[BUFFER] = "music/evening";
char night[BUFFER] = "music/night";
char saturday_morning[BUFFER] = "music/saturday/morning";
char saturday_afternoon[BUFFER] = "music/saturday/afternoon";
char saturday_evening[BUFFER] = "music/saturday/evening";
char saturday_night[BUFFER] = "music/saturday/night";
char sunday_morning[BUFFER] = "music/sunday/morning";
char sunday_afternoon[BUFFER] = "music/sunday/afternoon";
char sunday_evening[BUFFER] = "music/sunday/evening";
char sunday_night[BUFFER] = "music/sunday/night";

char *music_files[MAX_FILES]; int music_count = 0;
char *wav_files[MAX_FILES]; int wav_count = 0;
char *script_files[MAX_FILES]; int script_count = 0;

int current_day_state = -1;
char current_song[BUFFER] = "";
char next_song[BUFFER] = "";
int song_duration = 0;
time_t song_start_time = 0;
int paused_position = 0;

static long bytes_sent = 0;
static time_t last_sec = 0;

int running = 1;
int notif_playing = 0;

int mic_active = 0;
SDL_AudioDeviceID mic_dev = 0;
Uint8 micbuf[8192];
SDL_AudioSpec mic_want, mic_have;
static short mic_accum[MP3_FRAME_SAMPLES * 2];
static int accum_samples = 0;

int active_start_h=0, active_start_m=0;
int active_end_h=23, active_end_m=59;

typedef struct {
    SOCKET sock;
    char *buffer;
    int buf_size;
    int buf_used;
    time_t last_active;
    struct sockaddr_in addr;
    char ip_str[64];
} Client;

Client clients[MAX_CLIENT];
int client_count = 0;

enum {
    DAYSTATE_NIGHT = 0,
    DAYSTATE_MORNING,
    DAYSTATE_AFTERNOON,
    DAYSTATE_EVENING,
    DAYSTATE_SATURDAY,
    DAYSTATE_SUNDAY
};

enum LogColorLevel {
	LOG_RED,
	LOG_GREEN,
	LOG_YELLOW,
	LOG_BLUE,
	LOG_PURPLE,
	LOG_CYAN,
	LOG_WHITE
};

#ifdef _WIN32
CRITICAL_SECTION client_lock;
#else
pthread_mutex_t client_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

lame_t lame;
unsigned char mp3buf[8192];

void msleep(int ms) {
#ifdef _WIN32
	Sleep(ms);
#else
	usleep(ms * 1000);
#endif
}

#ifdef _WIN32
void title() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;

    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;

	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("=====================================================================\n");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("| ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED); printf ("OTAKU ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN); printf ("WEBRADIO ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE); printf ("SERVER ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("| ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_BLUE); printf ("A simple and easy to use webradio server!");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf (" |\n");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("=====================================================================\n");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("| ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); printf ("               Programmed by Martin D. (Rikku2000)               ");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf (" |\n");
	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); printf ("=====================================================================\n\n");

    SetConsoleTextAttribute(hConsole, saved_attributes);
}
#else
void title() {
    printf(YELLOW "=====================================================================\n" RESET);
    printf(YELLOW "| " RESET);
    printf(RED "OTAKU " RESET);
    printf(GREEN "WEBRADIO " RESET);
    printf(CYAN "SERVER " RESET);
    printf(YELLOW "| " RESET);
    printf(BLUE "A simple and easy to use webradio server!" RESET);
    printf(YELLOW " |\n" RESET);
    printf(YELLOW "=====================================================================\n" RESET);
    printf(YELLOW "| " RESET);
    printf(WHITE "               Programmed by Martin D. (Rikku2000)               " RESET);
    printf(YELLOW " |\n" RESET);
    printf(YELLOW "=====================================================================\n\n" RESET);
}
#endif

void logmsg(enum LogColorLevel level, int timed, const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "[%d.%m.%Y / %H:%M:%S]: ", t);

    va_list args;
    va_start(args, fmt);

#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;

    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;

    switch (level) {
        case LOG_RED: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED); break;
        case LOG_GREEN: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN); break;
        case LOG_YELLOW: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN); break;
        case LOG_BLUE: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_BLUE); break;
        case LOG_PURPLE: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE); break;
        case LOG_CYAN: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
        case LOG_WHITE: SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
    }

	if (timed == 1)
		printf("%s", timestr);
    vprintf(fmt, args);

    SetConsoleTextAttribute(hConsole, saved_attributes);
#else
    const char *color = "\033[0m";
    switch (level) {
        case LOG_RED: color = "\033[31m"; break;
        case LOG_GREEN: color = "\033[32m"; break;
        case LOG_YELLOW: color = "\033[33m"; break;
        case LOG_BLUE: color = "\033[34m"; break;
        case LOG_PURPLE: color = "\033[35m"; break;
        case LOG_CYAN: color = "\033[36m"; break;
        case LOG_WHITE: color = "\033[37m"; break;
    }

	if (timed == 1)
		printf("%s%s", color, timestr);
	else
		printf("%s", color);
    vprintf(fmt, args);
    printf("\033[0m");
#endif

    va_end(args);
}

void handle_sigint(int sig){ running=0; }

void load_config(const char *file){
    FILE *f = fopen(file,"r");
    if(!f){ logmsg (LOG_RED, 1, "No config file, using defaults\n"); return; }
    char line[BUFFER]; char key[BUFFER]; char val[BUFFER];
    while(fgets(line,sizeof(line),f)){
        if(sscanf(line,"%[^=]=%s",key,val)==2){
            if(strcmp(key,"shuffle")==0) shuffle=atoi(val);
            else if(strcmp(key,"shuffle_morning")==0) shuffle_morning=atoi(val);
            else if(strcmp(key,"shuffle_afternoon")==0) shuffle_afternoon=atoi(val);
            else if(strcmp(key,"shuffle_evening")==0) shuffle_evening=atoi(val);
            else if(strcmp(key,"shuffle_night")==0) shuffle_night=atoi(val);
            else if(strcmp(key,"shuffle_weekend")==0) shuffle_weekend=atoi(val);
            else if(strcmp(key,"scan_interval")==0) scan_interval=atoi(val);
            else if(strcmp(key,"fade_time")==0) fade_time=atoi(val);
            else if(strcmp(key,"enable_scripts")==0) enable_scripts=atoi(val);
            else if(strcmp(key,"stream_port")==0) stream_port=atoi(val);
            else if(strcmp(key,"enable_webui")==0) enable_webui=atoi(val);
            else if(strcmp(key,"webui_port")==0) webui_port=atoi(val);
            else if(strcmp(key,"webui_folder")==0) strncpy(webui_folder,val,BUFFER);
            else if(strcmp(key,"enable_ssl")==0) enable_ssl=atoi(val);
            else if(strcmp(key,"ssl_cert_file")==0) strncpy(ssl_cert_file,val,BUFFER);
            else if(strcmp(key,"ssl_cert_file")==0) strncpy(ssl_cert_file,val,BUFFER);
            else if(strcmp(key,"max_clients")==0) max_clients=atoi(val);
			else if(strcmp(key,"client_buffer_kb")==0) client_buffer_kb=atoi(val);
			else if(strcmp(key,"client_timeout_sec")==0) client_timeout_sec=atoi(val);
			else if(strcmp(key,"ptt_enable")==0) ptt_enable=atoi(val);
            else if(strcmp(key,"ptt_key")==0) strncpy(ptt_key,val,BUFFER);
			else if(strcmp(key,"ptt_volume")==0) ptt_volume=atoi(val);
			else if(strcmp(key,"music_duck")==0) music_duck=atoi(val);
			else if(strcmp(key,"stream_bitrate")==0) stream_bitrate=atoi(val);
			else if(strcmp(key,"frame_pacing")==0) frame_pacing=atoi(val);
			else if(strcmp(key,"active_start")==0) sscanf(val,"%d:%d",&active_start_h,&active_start_m);
			else if(strcmp(key,"active_end")==0) sscanf(val,"%d:%d",&active_end_h,&active_end_m);
            else if(strcmp(key,"notification_mode")==0) strncpy(notification_mode,val,16);
			else if(strcmp(key,"music_folder")==0) strncpy(music_folder,val,BUFFER);
            else if(strcmp(key,"notification_folder")==0) strncpy(notif_folder,val,BUFFER);
            else if(strcmp(key,"morning")==0) strncpy(morning,val,BUFFER);
            else if(strcmp(key,"afternoon")==0) strncpy(afternoon,val,BUFFER);
            else if(strcmp(key,"evening")==0) strncpy(evening,val,BUFFER);
            else if(strcmp(key,"night")==0) strncpy(night,val,BUFFER);
            else if(strcmp(key,"saturday_morning")==0) strncpy(saturday_morning,val,BUFFER);
            else if(strcmp(key,"saturday_afternoon")==0) strncpy(saturday_afternoon,val,BUFFER);
            else if(strcmp(key,"saturday_evening")==0) strncpy(saturday_evening,val,BUFFER);
            else if(strcmp(key,"saturday_night")==0) strncpy(saturday_night,val,BUFFER);
            else if(strcmp(key,"sunday_morning")==0) strncpy(sunday_morning,val,BUFFER);
            else if(strcmp(key,"sunday_afternoon")==0) strncpy(sunday_afternoon,val,BUFFER);
            else if(strcmp(key,"sunday_evening")==0) strncpy(sunday_evening,val,BUFFER);
            else if(strcmp(key,"sunday_night")==0) strncpy(sunday_night,val,BUFFER);
        }
    }
    fclose(f);
}

#ifdef _WIN32
char* utf16_to_utf8(const wchar_t* wstr) {
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if(size <= 0) return NULL;
    char* utf8 = (char*)malloc(size);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, utf8, size, NULL, NULL);
    return utf8;
}
#endif

int scan_folder(char **list,int *count,const char *folder,const char *ext)
{
#ifdef _WIN32
    WIN32_FIND_DATAW fdFile; HANDLE hFind; wchar_t sPath[BUFFER];
    swprintf(sPath, BUFFER, L"%hs\\*%hs", folder, ext);
    hFind = FindFirstFileW(sPath,&fdFile);
    if(hFind==INVALID_HANDLE_VALUE) return 0;
    int added=0;
    do {
        if(!(fdFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)){
            wchar_t fullPathW[BUFFER];
            swprintf(fullPathW, BUFFER, L"%hs\\%s", folder, fdFile.cFileName);
            char* pathU8 = utf16_to_utf8(fullPathW);
            if(pathU8){ list[(*count)++] = pathU8; added++; }
        }
    } while(FindNextFileW(hFind,&fdFile));
    FindClose(hFind);
    return added;
#else
    DIR *d = opendir(folder); struct dirent *de; int added=0;
    if(!d) return 0;
    while((de=readdir(d))){
        if(strstr(de->d_name,ext)){
            char path[BUFFER]; snprintf(path,BUFFER,"%s/%s",folder,de->d_name);
            list[(*count)++] = strdup(path); added++;
        }
    }
    closedir(d);
    return added;
#endif
}

void parse_time(const char *filename,int *hour,int *min)
{
#ifdef _WIN32
    *hour=0; *min=0; const char *base = strrchr(filename, '\\');
#else
    *hour=0; *min=0; const char *base = strrchr(filename, '/');
#endif
    if(base) base++; else base=filename;
    sscanf(base,"%d_%d",&(*hour),&(*min));
}

int should_trigger(const char *file)
{
    int h,m; parse_time(file,&h,&m);
    time_t t=time(NULL); struct tm *tmnow = localtime(&t);
    return (tmnow->tm_hour==h && tmnow->tm_min==m);
}

void run_script(const char *file)
{
    logmsg(LOG_GREEN, 1, "Running script: %s\n",file);
#ifdef _WIN32
    char cmd[BUFFER]; snprintf(cmd,BUFFER,"cmd /C \"%s\"",file); system(cmd);
#else
    char cmd[BUFFER]; snprintf(cmd,BUFFER,"sh \"%s\"",file); system(cmd);
#endif
}

int get_mp3_duration(const char *filename) {
    if (!filename) return 0;

    FILE *f = fopen(filename, "rb");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (filesize <= 0) {
        fclose(f);
        return 0;
    }

    unsigned char header[10];
    if (fread(header, 1, 10, f) == 10 && memcmp(header, "ID3", 3) == 0) {
        int tagSize = (header[6] & 0x7F) << 21 |
                      (header[7] & 0x7F) << 14 |
                      (header[8] & 0x7F) << 7  |
                      (header[9] & 0x7F);
        fseek(f, 10 + tagSize, SEEK_SET);
    } else {
        fseek(f, 0, SEEK_SET);
    }

    unsigned char hdr[4];
    int found = 0, mpegver = 0, layer = 0, br_index = 0, sr_index = 0, channel_mode = 0;

    while (fread(hdr, 1, 4, f) == 4) {
        if (hdr[0] == 0xFF && (hdr[1] & 0xE0) == 0xE0) {
            mpegver     = (hdr[1] >> 3) & 3;
            layer       = (hdr[1] >> 1) & 3;
            br_index    = (hdr[2] >> 4) & 0x0F;
            sr_index    = (hdr[2] >> 2) & 0x03;
            channel_mode= (hdr[3] >> 6) & 0x03;
            found = 1;
            break;
        }
        fseek(f, -3, SEEK_CUR);
    }

    if (!found) {
        fclose(f);
        return 0;
    }

    static const int sr_tbl_mpeg1[4] = {44100, 48000, 32000, 0};
    static const int sr_tbl_mpeg2[4] = {22050, 24000, 16000, 0};
    static const int sr_tbl_mpeg25[4] = {11025, 12000, 8000, 0};

    int samplerate = 0;
    if (mpegver == 3) samplerate = sr_tbl_mpeg1[sr_index];
    else if (mpegver == 2) samplerate = sr_tbl_mpeg2[sr_index];
    else if (mpegver == 0) samplerate = sr_tbl_mpeg25[sr_index];

    int samples_per_frame = (mpegver == 3) ? 1152 : 576;

    int sideinfo = (mpegver == 3) ? ((channel_mode == 3) ? 17 : 32)
                                  : ((channel_mode == 3) ? 9  : 17);

    fseek(f, 4 + sideinfo, SEEK_CUR);
    char xing[4];
    if (fread(xing, 1, 4, f) == 4 && (!memcmp(xing, "Xing", 4) || !memcmp(xing, "Info", 4))) {
        unsigned char flags[4];
        if (fread(flags, 1, 4, f) == 4) {
            unsigned int fval = (flags[0] << 24) | (flags[1] << 16) | (flags[2] << 8) | flags[3];
            if (fval & 0x0001) {
                unsigned char fb[4];
                if (fread(fb, 1, 4, f) == 4) {
                    unsigned int frames = (fb[0] << 24) | (fb[1] << 16) | (fb[2] << 8) | fb[3];
                    if (frames > 0 && samplerate > 0) {
                        fclose(f);
                        long total_samples = (long)frames * samples_per_frame;
                        return (int)(total_samples / samplerate);
                    }
                }
            }
        }
    }

    fseek(f, 32, SEEK_CUR);
    char vbri[4];
    if (fread(vbri, 1, 4, f) == 4 && !memcmp(vbri, "VBRI", 4)) {
        fseek(f, 6, SEEK_CUR);
        unsigned char fb[4];
        if (fread(fb, 1, 4, f) == 4) {
            unsigned int frames = (fb[0] << 24) | (fb[1] << 16) | (fb[2] << 8) | fb[3];
            if (frames > 0 && samplerate > 0) {
                fclose(f);
                long total_samples = (long)frames * samples_per_frame;
                return (int)(total_samples / samplerate);
            }
        }
    }

    static const int br_tbl_mpeg1[16] = {0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0};
    static const int br_tbl_mpeg2[16] = {0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0};
    int bitrate = (mpegver == 3) ? br_tbl_mpeg1[br_index] : br_tbl_mpeg2[br_index];
    fclose(f);

    if (bitrate > 0) {
        return (int)((filesize * 8) / (bitrate * 1000L));
    }

    return 0;
}

void get_display_name(const char *path, char *out, int max)
{
#ifdef _WIN32
    const char *base = strrchr(path, '\\');
#else
    const char *base = strrchr(path, '/');
#endif
    if(base) base++; else base = path;
    strncpy(out, base, max-1);
    out[max-1] = '\0';
    char *dot = strrchr(out, '.');
    if(dot) *dot = '\0';
}

void add_client(SOCKET s){
#ifdef _WIN32
    EnterCriticalSection(&client_lock);
#else
    pthread_mutex_lock(&client_lock);
#endif
    if(client_count < max_clients){

#ifdef _WIN32
		u_long mode = 1;
		ioctlsocket(s, FIONBIO, &mode);
#else
		fcntl(s, F_SETFL, O_NONBLOCK);
#endif

		clients[client_count].sock = s;
		clients[client_count].buf_size = client_buffer_kb * 1024;
		clients[client_count].buffer = (char*)malloc(clients[client_count].buf_size);
		clients[client_count].buf_used = 0;
		clients[client_count].last_active = time(NULL);
		client_count++;

		logmsg(LOG_PURPLE, 1, "Client added (%d/%d)\n",client_count,max_clients);
	}
    else { logmsg(LOG_YELLOW, 1, "Client refused\n"); close_socket(s);}
#ifdef _WIN32
    LeaveCriticalSection(&client_lock);
#else
    pthread_mutex_unlock(&client_lock);
#endif
}

int stream_send(int sock, const char *buf, int len, int bitrate_kbps, int samplerate, int frame_pacing) {
    static long sent_this_sec = 0;
    static time_t last_sec = 0;
    int sent = 0;

    long max_bytes = (bitrate_kbps * 1000) / 8;

    time_t now = time(NULL);
    if (now != last_sec) {
        last_sec = now;
        sent_this_sec = 0;
    }

    if (frame_pacing) {
        int samples_per_frame = 1152;
        double frame_duration_ms = (double)samples_per_frame * 1000.0 / samplerate;

        int frame_size = (144 * (bitrate_kbps * 1000)) / samplerate;
        if (frame_size <= 0) frame_size = 418;

        int offset = 0;
        while (offset < len) {
            int chunk = (len - offset > frame_size) ? frame_size : (len - offset);

            sent = send(sock, buf + offset, chunk, 0);
            if (sent <= 0) return sent;

            offset += chunk;
            sent_this_sec += chunk;

            msleep((int)frame_duration_ms);
        }
    } else {
        if (sent_this_sec + len > max_bytes) {
            msleep(50);
        }
        sent = send(sock, buf, len, 0);
        sent_this_sec += len;
    }

    return sent;
}

void broadcast(unsigned char *buf, int len) {
    for (int i = 0; i < client_count; ) {
        Client *c = &clients[i];

        if (c->buf_used + len < c->buf_size) {
            memcpy(c->buffer + c->buf_used, buf, len);
            c->buf_used += len;
        } else {
            if (time(NULL) - c->last_active > client_timeout_sec) {
                logmsg(LOG_PURPLE, 1, "Client too slow, disconnecting\n");
                close_socket(c->sock);
                free(c->buffer);
                clients[i] = clients[--client_count];
                continue;
            }
        }

        if (c->buf_used > 0) {
            int sent = stream_send(c->sock, c->buffer, c->buf_used, stream_bitrate, 44100, frame_pacing);
            if (sent > 0) {
                if (sent < c->buf_used) {
                    memmove(c->buffer, c->buffer + sent, c->buf_used - sent);
                }
                c->buf_used -= sent;
                c->last_active = time(NULL);
            } else if (sent < 0) {
#ifdef _WIN32
                if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
                if (errno != EWOULDBLOCK && errno != EAGAIN)
#endif
                {
                    logmsg(LOG_PURPLE, 1, "Client disconnected\n");
                    close_socket(c->sock);
                    free(c->buffer);
                    clients[i] = clients[--client_count];
                    continue;
                }
            }
        }

        i++;
    }
}

void pcm_callback(void *userdata, Uint8 *stream,int len){
    int mp3bytes=lame_encode_buffer_interleaved(lame,(short*)stream,len/4,mp3buf,sizeof(mp3buf));
    if(mp3bytes>0) broadcast(mp3buf,mp3bytes);
}

int next_index(int current){ if(shuffle && music_count>1){ int idx; do{ idx=rand()%music_count; }while(idx==current); return idx; } return (current+1)%music_count; }

thread_return stream_server(void *arg)
{
#ifdef _WIN32
    WSADATA wsa;
	WSAStartup(MAKEWORD(2,2),&wsa);
#endif
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM,0);
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET; addr.sin_port=htons(stream_port); addr.sin_addr.s_addr=INADDR_ANY;
    bind(server_fd,(struct sockaddr*)&addr,sizeof(addr));
    listen(server_fd,5);
    logmsg(LOG_GREEN, 1, "Streaming server port %d\n",stream_port);

    while(running){
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        SOCKET client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if(client_fd==INVALID_SOCKET) continue;

        char client_ip[64];
#ifdef _WIN32
        strcpy(client_ip, inet_ntoa(client_addr.sin_addr));
#else
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
#endif

        logmsg(LOG_PURPLE, 1, "New client connected: %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        char header[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: audio/mpeg\r\n"
            "Cache-Control: no-cache\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Access-Control-Allow-Methods: GET, OPTIONS\r\n"
			"Access-Control-Allow-Headers: Content-Type\r\n"
            "Connection: keep-alive\r\n\r\n";
        send(client_fd, header, (int)strlen(header), 0);

        add_client(client_fd);
    }
    close_socket(server_fd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

thread_return status_server(void *arg)
{
#ifdef _WIN32
    WSADATA wsa;
	WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM,0);
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET; addr.sin_port=htons(status_port); addr.sin_addr.s_addr=INADDR_ANY;
    bind(server_fd,(struct sockaddr*)&addr,sizeof(addr));
    listen(server_fd,5);
    logmsg(LOG_GREEN, 1, "Status server port %d\n",status_port);

    char buf[1024]; char resp[2048]; int elapsed; SOCKET client_fd;
    while(running){
        client_fd=accept(server_fd,NULL,NULL); if(client_fd==INVALID_SOCKET) continue;
        recv(client_fd,buf,sizeof(buf)-1,0);

        char songname[BUFFER], nextname[BUFFER];
        get_display_name(current_song,songname,BUFFER);
        get_display_name(next_song,nextname,BUFFER);
        elapsed=(int)(time(NULL)-song_start_time);

        snprintf(resp,sizeof(resp),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n"
            "{ \"song\":\"%s\",\"duration\":%d,\"elapsed\":%d,\"next\":\"%s\",\"listeners\":%d,\"slots\":%d }\n",
            songname,song_duration,elapsed,nextname,client_count,max_clients);
        send(client_fd,resp,(int)strlen(resp),0);
        close_socket(client_fd);
    }
    close_socket(server_fd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

void pick_random_folder(const char *list,char*out){
    if(strlen(list)==0){ out[0]='\0'; return; }
    char temp[BUFFER]; strncpy(temp,list,BUFFER);
    char*tokens[32]; int c=0;
    char*tok=strtok(temp,",");
    while(tok&&c<32){ tokens[c++]=tok; tok=strtok(NULL,","); }
    if(c>0){ int ch=rand()%c; strncpy(out,tokens[ch],BUFFER); }
    else { out[0]='\0'; }
}

int get_shuffle_setting(){
    time_t t=time(NULL); struct tm*tmnow=localtime(&t);
    int h=tmnow->tm_hour,w=tmnow->tm_wday;
    if(w==0||w==6) return (shuffle_weekend>=0?shuffle_weekend:shuffle);
    if(h>=6&&h<12) return (shuffle_morning>=0?shuffle_morning:shuffle);
    if(h>=12&&h<18) return (shuffle_afternoon>=0?shuffle_afternoon:shuffle);
    if(h>=18&&h<24) return (shuffle_evening>=0?shuffle_evening:shuffle);
    return (shuffle_night>=0?shuffle_night:shuffle);
}

void select_music_folder(char*out){
    time_t t=time(NULL); struct tm*tmnow=localtime(&t);
    int h=tmnow->tm_hour,w=tmnow->tm_wday;
    if(w==6){
		if(h>=6&&h<12&&strlen(saturday_morning)>0)
			pick_random_folder(saturday_morning,out);
		else if(h>=12&&h<18&&strlen(saturday_afternoon)>0)
			pick_random_folder(saturday_afternoon,out);
		else if(h>=18&&h<24&&strlen(saturday_evening)>0)
			pick_random_folder(saturday_evening,out);
		else if(strlen(saturday_night)>0)
			pick_random_folder(saturday_night,out);

		return;
	} else if(w==0){
		if(h>=6&&h<12&&strlen(sunday_morning)>0)
			pick_random_folder(morning,out);
		else if(h>=12&&h<18&&strlen(sunday_afternoon)>0)
			pick_random_folder(sunday_afternoon,out);
		else if(h>=18&&h<24&&strlen(sunday_evening)>0)
			pick_random_folder(sunday_evening,out);
		else if(strlen(sunday_night)>0)
			pick_random_folder(sunday_night,out);

		return;
	} else if(h>=6&&h<12&&strlen(morning)>0) pick_random_folder(morning,out);
    else if(h>=12&&h<18&&strlen(afternoon)>0) pick_random_folder(afternoon,out);
    else if(h>=18&&h<24&&strlen(evening)>0) pick_random_folder(evening,out);
    else if(strlen(night)>0) pick_random_folder(night,out);
    else strncpy(out,music_folder,BUFFER);
}

int get_day_state() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    int h = t->tm_hour;

    if (t->tm_wday == 6)
		return DAYSTATE_SATURDAY;
    if (t->tm_wday == 0)
		return DAYSTATE_SUNDAY;

    if (h >= 6 && h < 12)
		return DAYSTATE_MORNING;

    if (h >= 12 && h < 18)
		return DAYSTATE_AFTERNOON;

    if (h >= 18 && h < 24)
		return DAYSTATE_EVENING;

    return DAYSTATE_NIGHT;
}

int is_active_time() {
    time_t t=time(NULL);
    struct tm *tmnow=localtime(&t);
    int now = tmnow->tm_hour*60 + tmnow->tm_min;
    int start = active_start_h*60 + active_start_m;
    int end   = active_end_h*60 + active_end_m;

    if(start <= end)
        return (now >= start && now < end);
    else
        return (now >= start || now < end);
}

void handle_http_client(int csock) {
    char req[1024];
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(csock, &fds);
    tv.tv_sec = 2; tv.tv_usec = 0;

	int sel = select(csock+1, &fds, NULL, NULL, &tv);
	if (sel <= 0) { close_socket(csock); return; }

	int r = recv(csock, req, sizeof(req)-1, 0);
	if (r <= 0) { close_socket(csock); return; }
	req[r] = 0;

    char filename[256] = "index.html";
    if (sscanf(req, "GET /%255s", filename) == 1) {
        if (strcmp(filename, "/") == 0 || strcmp(filename, "") == 0)
            strcpy(filename, "/index.html");
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", webui_folder, filename);

    const char *ctype = "text/html";
    if (strstr(filename, ".css")) ctype = "text/css";
    else if (strstr(filename, ".js")) ctype = "application/javascript";
    else if (strstr(filename, ".png")) ctype = "image/png";
    else if (strstr(filename, ".jpeg")) ctype = "image/jpeg";
    else if (strstr(filename, ".jpg")) ctype = "image/jpg";
	else if (strstr(filename, ".mp4")) ctype = "video/mpeg";
    else if (strstr(filename, ".ico")) ctype = "image/x-icon";
    else if (strstr(filename, ".svg")) ctype = "image/svg+xml";
    else if (strstr(filename, ".json")) ctype = "application/json";

    FILE *f = fopen(path, "rb");
    if (!f) {
        const char *resp = "HTTP/1.1 404 Not Found\r\n"
                           "Connection: close\r\n\r\nNot Found";
        send(csock, resp, (int)strlen(resp), 0);
        close_socket(csock);
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char header[512];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n"
             "Connection: close\r\n"
             "Access-Control-Allow-Origin: *\r\n\r\n",
             ctype, size);
    send(csock, header, (int)strlen(header), 0);

    char buf[4096];
    int n;
    while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0) {
        int sent = send(csock, buf, n, 0);
        if (sent <= 0) break;
    }
    fclose(f);
    close_socket(csock);
}

#ifdef HTTP_SSL
void handle_https_client(SSL *ssl) {
    char req[1024];
    int r = SSL_read(ssl, req, sizeof(req) - 1);
    if (r <= 0) {
        return;
    }
    req[r] = 0;

    char method[8], path[256];
    if (sscanf(req, "%7s %255s", method, path) != 2) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nBad Request";
        SSL_write(ssl, resp, (int)strlen(resp));
        return;
    }

    if (strcmp(path, "/") == 0) strcpy(path, "/index.html");

    char filename[512];
    snprintf(filename, sizeof(filename), "%s%s", webui_folder, path);

    FILE *f = fopen(filename, "rb");
    if (!f) {
        const char *resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nNot Found";
        SSL_write(ssl, resp, (int)strlen(resp));
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    const char *ctype = "text/html";
    if (strstr(filename, ".css")) ctype = "text/css";
    else if (strstr(filename, ".js")) ctype = "application/javascript";
    else if (strstr(filename, ".png")) ctype = "image/png";
    else if (strstr(filename, ".jpeg")) ctype = "image/jpeg";
    else if (strstr(filename, ".jpg")) ctype = "image/jpg";
	else if (strstr(filename, ".mp4")) ctype = "video/mpeg";
    else if (strstr(filename, ".ico")) ctype = "image/x-icon";
    else if (strstr(filename, ".svg")) ctype = "image/svg+xml";
    else if (strstr(filename, ".json")) ctype = "application/json";

    char header[512];
    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n",
        ctype, size);
    SSL_write(ssl, header, (int)strlen(header));

    char buf[4096];
    int n;
    while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0) {
        if (SSL_write(ssl, buf, n) <= 0) break;
    }
    fclose(f);
}
#endif

thread_return webui_thread(void *arg)
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    int wsock = socket(AF_INET, SOCK_STREAM, 0);
    if (wsock < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(webui_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    int yes = 1;
    setsockopt(wsock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

    if (bind(wsock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close_socket(wsock);
        return 0;
    }

    listen(wsock, 10);
    logmsg(LOG_GREEN, 1, "Web UI running on port %d\n", webui_port);

    while (running) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int csock = accept(wsock, (struct sockaddr*)&cli, &clen);
        if (csock < 0) continue;

#ifdef HTTP_SSL
		if (enable_ssl) {
			SSL *ssl = SSL_new(ssl_ctx);
			SSL_set_fd(ssl, csock);
			if (SSL_accept(ssl) <= 0) {
				SSL_free(ssl);
				close_socket(csock);
				continue;
			}
			handle_https_client(ssl);
			SSL_shutdown(ssl);
			SSL_free(ssl);
		} else
			handle_http_client(csock);
#else
        handle_http_client(csock);
#endif
    }

    close_socket(wsock);
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

int is_ptt_pressed() {
#ifdef _WIN32
	return (GetAsyncKeyState(VK_SPACE) & 0x8000) != 0;
#else
	struct timeval tv = {0L, 0L};
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(0, &fds);
	if (select(1, &fds, NULL, NULL, &tv) > 0) {
		char c;
		if (read(0, &c, 1) > 0)
			if (c == ' ')
				return 1;
	}

	return 0;
#endif
}

void handle_ptt () {
	if (ptt_enable && is_ptt_pressed()) {
		if (!mic_active) {
			logmsg(LOG_GREEN, 1, "PTT ON (microphone opened)\n");
			mic_dev = SDL_OpenAudioDevice(NULL, 1, &mic_want, &mic_have, 0);
			if (!mic_dev) {
				logmsg(LOG_RED, 1, "PTT: Failed to open mic: %s\n", SDL_GetError());
			} else {
				SDL_PauseAudioDevice(mic_dev, 0);
				Mix_VolumeMusic((MIX_MAX_VOLUME * music_duck) / 100);
				mic_active = 1;
			}
		}

		if (mic_active) {
			int got = SDL_DequeueAudio(mic_dev, micbuf, sizeof(micbuf));
			if (got > 0) {
				int samples = got / (sizeof(short) * mic_have.channels);
				short *pcm_in = (short *)micbuf;

				for (int i = 0; i < samples; i++) {
					mic_accum[accum_samples++] = pcm_in[i];

					if (accum_samples >= MP3_FRAME_SAMPLES * mic_have.channels) {
						int mp3bytes = lame_encode_buffer_interleaved(lame,mic_accum,MP3_FRAME_SAMPLES,mp3buf,sizeof(mp3buf));
						if (mp3bytes > 0)
							broadcast(mp3buf, mp3bytes);

						accum_samples = 0;
					}
				}
			}
		}
	} else {
		if (mic_active) {
			int mp3bytes = lame_encode_flush(lame, mp3buf, sizeof(mp3buf));
			if (mp3bytes > 0) {
				broadcast(mp3buf, mp3bytes);
			}
			accum_samples = 0;
		}
	}
}

int main(int argc, char **argv) {
    srand((unsigned int)time(NULL));
    signal(SIGINT,handle_sigint);

	title();

    load_config("webradio.cfg");

#ifdef _WIN32
    InitializeCriticalSection(&client_lock);
#else
    pthread_mutex_init(&client_lock,NULL);
#endif

    if(SDL_Init(SDL_INIT_AUDIO)<0){ logmsg(LOG_RED, 1, "SDL init error\n"); return 1; }
    if(Mix_OpenAudio(44100,MIX_DEFAULT_FORMAT,2,2048)<0){ logmsg(LOG_RED, 1, "Mixer init error\n"); return 1; }

	if (ptt_enable) {
		SDL_zero(mic_want);
		mic_want.freq = 44100;
		mic_want.format = AUDIO_S16SYS;
		mic_want.channels = 2;
		mic_want.samples = 1024;
		if (mic_have.freq != 44100 || mic_have.channels != 2)
			logmsg(LOG_RED, 1, "Mic format mismatch! SDL gave %d Hz %d channels\n", mic_have.freq, mic_have.channels);
	}

	char folder[BUFFER]; select_music_folder(folder);
	music_count=0; scan_folder(music_files,&music_count,folder,".mp3");
	if(music_count==0){
		logmsg(LOG_RED, 1, "No music in %s\n",folder);
		scan_folder(music_files,&music_count,music_folder,".mp3");
		logmsg(LOG_YELLOW, 1, "Try to fallback in %s\n",music_folder);
		msleep(1000);
	}
	int do_shuffle=get_shuffle_setting();
    scan_folder(wav_files,&wav_count,notif_folder,".wav");

#ifdef _WIN32
    if(enable_scripts) scan_folder(script_files,&script_count,notif_folder,".bat");
#else
    if(enable_scripts) scan_folder(script_files,&script_count,notif_folder,".sh");
#endif
    logmsg(LOG_GREEN, 1, "Loaded %d MP3s, %d WAVs, %d scripts\n",music_count,wav_count,script_count);

    lame=lame_init();
	lame_set_in_samplerate(lame,44100);
	lame_set_num_channels(lame,2);
    lame_set_brate(lame,128);
	lame_set_mode(lame,STEREO);
	lame_set_quality(lame,2);
    lame_init_params(lame);

    Mix_SetPostMix(pcm_callback,NULL);

#ifdef _WIN32
    HANDLE hStream = CreateThread(NULL,0,stream_server,NULL,0,NULL);
    HANDLE hStatus = CreateThread(NULL,0,status_server,NULL,0,NULL);
#else
    pthread_t tid1,tid2;
    pthread_create(&tid1,NULL,stream_server,NULL); pthread_detach(tid1);
    pthread_create(&tid2,NULL,status_server,NULL); pthread_detach(tid2);
#endif

	if (enable_webui) {
#ifdef HTTP_SSL
		if (enable_ssl) {
			SSL_library_init();
			OpenSSL_add_all_algorithms();
			SSL_load_error_strings();
			ssl_ctx = SSL_CTX_new(TLS_server_method());
			if (!ssl_ctx) {
				logmsg(LOG_YELLOW, 1, "Failed to create SSL context");
				return 0;
			}
			if (SSL_CTX_use_certificate_file(ssl_ctx, ssl_cert_file, SSL_FILETYPE_PEM) <= 0 || SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_key_file, SSL_FILETYPE_PEM) <= 0) {
				logmsg(LOG_YELLOW, 1, "Failed to load SSL cert/key");
				return 0;
			}
		}
#endif
#ifdef _WIN32
		CreateThread(NULL, 0, webui_thread, NULL, 0, NULL);
#else
		pthread_t tid3;
		pthread_create(&tid3, NULL, webui_thread, NULL);
#endif
	}

	int i, idx = 0;
    if(music_count>1)
		idx=do_shuffle?rand()%music_count:0;

    while(music_count > 0 && running){
		int day_state = get_day_state();

		if ((day_state != current_day_state)) {
			logmsg(LOG_GREEN, 1, "Daytime changed, rescanning music folder\n");
			select_music_folder(folder);
			music_count=0;
			scan_folder(music_files,&music_count,folder,".mp3");
			if(music_count==0){
				scan_folder(music_files,&music_count,music_folder,".mp3");
				logmsg(LOG_YELLOW, 1, "Try to fallback in %s\n",music_folder);
			}
			logmsg(LOG_GREEN, 1, "Loaded %d MP3s\n",music_count);
			msleep(500);
			strncpy(current_song,music_files[idx],BUFFER);
			strncpy(next_song,music_files[next_index(idx)],BUFFER);
			current_day_state = day_state;
		} else {
			strncpy(current_song,music_files[idx],BUFFER);
			strncpy(next_song,music_files[next_index(idx)],BUFFER);
		}
		song_duration=get_mp3_duration(current_song);
		song_start_time=time(NULL);

		if (!is_active_time()) {
			if (Mix_PlayingMusic()) {
				Mix_HaltMusic();
				logmsg(LOG_GREEN, 1, "Radio is OFF (outside active hours %02d:%02d-%02d:%02d)\n",active_start_h, active_start_m, active_end_h, active_end_m);
			}
			msleep(10000);
			continue;
		} else
			handle_ptt ();

		Mix_Music *m=Mix_LoadMUS(current_song);
        if(m){
            logmsg(LOG_GREEN, 1, "Playing: %s (duration %d sec)\n",current_song,song_duration);
            Mix_PlayMusic(m,1);
            while(Mix_PlayingMusic() && running){
				for(i=0;i<wav_count;i++){
					if(should_trigger(wav_files[i])){
						logmsg(LOG_GREEN, 1, "Trigger WAV: %s\n",wav_files[i]);
						Mix_Chunk *c=Mix_LoadWAV(wav_files[i]);
						if(c){
							if(strcmp(notification_mode,"fade")==0){
								Mix_FadeOutMusic(fade_time);
								msleep(fade_time);
								Mix_PlayChannel(-1,c,0);
								while(Mix_Playing(-1)) msleep(100);
								Mix_FadeInMusic(m,1,fade_time);
								msleep(fade_time);
							} else {
								Mix_PlayChannel(-1,c,0);
								while(Mix_Playing(-1)) msleep(100);
							}
							Mix_FreeChunk(c);
						}
						msleep(60000);
					}
				}

				if(enable_scripts){
					for(i=0;i<script_count;i++){
						if(should_trigger(script_files[i])){
							if(strcmp(notification_mode,"fade")==0){
								Mix_FadeOutMusic(fade_time);
								msleep(fade_time);
								run_script(script_files[i]);
								Mix_FadeInMusic(m,1,fade_time);
								msleep(fade_time);
							} else {
								run_script(script_files[i]);
							}
							msleep(60000);
						}
					}
				}

				handle_ptt ();

                msleep(500);
            }
            Mix_FreeMusic(m);
        }
        idx=next_index(idx);
    }

	for (int i = 0; i < client_count; i++) {
		close_socket(clients[i].sock);
		free(clients[i].buffer);
	}
	client_count = 0;

    Mix_CloseAudio(); SDL_Quit(); lame_close(lame);
#ifdef _WIN32
    DeleteCriticalSection(&client_lock);
#else
    pthread_mutex_destroy(&client_lock);
#endif
    return 0;
}
