#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <atomic>
#include <map>
#include <sstream>
#include <thread>
#include <mutex>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <algorithm>

using namespace std;
std::atomic<bool> pow_found(false);
std::atomic<long long> total_hashes(0);
string solved_suffix = "";
mutex result_mtx;
const char* SERVER_IP = "18.202.148.130";
const int SERVER_PORT = 3336;
map<string, string> USER_DATA = {
    {"NAME","Hasini Mohan"},
    {"MAILNUM", "2"},
    {"MAIL1","hasinimohan2021@gmail.com"},
    {"MAIL2", "hasinihasinimohan@gmail.com"},
    {"SKYPE","NA"},
    {"BIRTHDATE","25-12-2003"},
    {"COUNTRY","India"},
    {"ADDRNUM","2"},
    {"ADDRLINE1","Kadai street,sembathaniruppu"},
    {"ADDRLINE2","Mayiladuthurai,609001"}
};
string trim(const string& s)
{
    size_t first = s.find_first_not_of(" \n\r\t");
    if (string::npos == first) return s;
    size_t last = s.find_last_not_of(" \n\r\t");
    return s.substr(first, (last - first + 1));

}
void write_log(const string& message)
{
    ofstream log_file("connection_log.txt",ios_base::app);
    if (log_file.is_open())
    {
        log_file.close();
    }
}
string sha1(string data)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)data.c_str(),data.length(),hash);
    char hex[41];
    for(int i=0; i<SHA_DIGEST_LENGTH; i++)
    {
        sprintf(&hex[i*2],"%02x", hash[i]);
    }
    return string(hex);
}
string random_suffix(int length = 10)
{
    static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYX0123456789!@#$%^&*()";
    string result = "";
    for(int i = 0; i<length; i++)
    {
        result += charset[rand() % (sizeof(charset)- 1)];
    }
    return result;
}
void pow_worker(string authdata, int diff, string prefix)
{
    srand(time(NULL) ^ (unsigned long)pthread_self());
    long long local_count = 0;
    while(!pow_found)
    {
        string suffix = random_suffix();
        local_count++;
        total_hashes++;
        string attempt = sha1(authdata + suffix);
        if (attempt.compare(0, diff,prefix) == 0)
        {
            lock_guard<mutex> lock(result_mtx);
            if(!pow_found)
            {
                 pow_found = true;
                 solved_suffix = suffix;
            }
            break;
        }
        if (local_count >= 10000)
        {
            total_hashes += local_count;
            local_count = 0;
            if (total_hashes % 5000000 == 0)
            {
                std::cout << "\r [*] Total Hashes : " << (total_hashes / 1000000) << " Million...." <<flush;
            }
        }
    }
}
void cleanup(SSL* ssl,int sock,SSL_CTX* ctx)
{
    if (ssl) SSL_free(ssl);
    if (sock != -1) close(sock);
    if (ctx) SSL_CTX_free(ctx);
    std::cout << "[!] Resources cleaned up. Connection closed." <<endl;
}
int main()
{
    srand(time(NULL));
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if(SSL_CTX_use_certificate_file(ctx, "cert.pem",SSL_FILETYPE_PEM)<= 0 || SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM)<= 0)
    {
        cerr << "[-] Error loading certificates!" << endl;
        return 1;
    }
    int sock = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    std::cout << "[*] Connecting to "<< SERVER_IP <<"..." <<endl;
    if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        perror ("[-] Connection failed!");
        return 1;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0)
    {
        cerr << "[-] TLS Handshake failed!" <<endl;
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf,sizeof(err_buf));
        cerr << "OpenSSL Error: " << err_buf << endl;
        ERR_print_errors_fp(stderr);
        cleanup(ssl, sock, ctx);
        return 1;
    }
    std::cout <<"[+] TLS connection established successfully." << endl;
    std::cout << "[+] Connected. Monitoring threads...." << endl;
    write_log("---NEW SESSION STRATED---");
    char buffer[4096] = {0};
    string authdata = "";
    while(true)
    {
        memset(buffer, 0, sizeof(buffer));
        int bytes = SSL_read(ssl , buffer, sizeof(buffer) - 1);
        if(bytes <= 0)
        {
            std::cout<< "\n[-] Server closed the connection unexpectedly or error occured." << endl;
            break; 
        }
        string line(buffer);
        std::cout << "S: " << line << endl;
        write_log("SERVER: " + line); 
        stringstream ss(line);
        string cmd, token, difficulty;
        ss >> cmd >> token >> difficulty;
        if (cmd == "HELO")
        {
            string resp = "EHLO\n";
            SSL_write(ssl, resp.c_str(), resp.length());
            write_log("CLIENT: EHLO");
        }
        else if(cmd == "POW")
        {
            authdata = token;
            int diff = stoi(difficulty);
            string prefix(diff, '0');
            pow_found = false;
            unsigned n_threads = thread::hardware_concurrency();
            std::cout << "[LOG]: Solving POW | Authdata: " << authdata << "| Difficulty: " << difficulty << endl; 
            std::cout << "[LOG]: Starting  " << n_threads << " threads for Difficulty " << diff << endl;
            vector<thread> worker_threads;
            for (unsigned int i = 0; i<n_threads; ++i )
            {
                worker_threads.push_back(thread(pow_worker, authdata, diff,prefix));
            }
            for(auto& t: worker_threads)
            {
                t.join();
            }
            std::cout << "\n [LOG]: Found Suffix: " << solved_suffix << endl;
            string resp = solved_suffix + "\n";
            SSL_write(ssl, resp.c_str(), resp.length());
            write_log("CLIENT POW SOLUTION: " + solved_suffix);
            std::cout << "[+] POW Solved: " << solved_suffix << endl;
        }
        else if(USER_DATA.count(cmd))
        {
            std::cout << "[LOG]: Processing Command: " << cmd << endl;
            string clean_token = trim(token);
            string response_hash = sha1(authdata + clean_token);
            string final_resp = response_hash+ " " + USER_DATA[cmd] + "\n";
            SSL_write(ssl, final_resp.c_str(),final_resp.length());
            std::cout << "C: " << final_resp;
            write_log("CLIENT DATA(" + cmd + "): " + final_resp);
            std::cout << "[LOG]< User data hashed. Total session hashes: " <<total_hashes << endl;
        }
        else if(line.find("END") != string::npos)
        {
            SSL_write(ssl,"OK\n", 3);
            std::cout << "\n [success] Server sent END. Submission finished." << endl;
            std::cout << "[*] Closing connection gracefully...." << endl;
            break;
        }
    }
    cleanup(ssl, sock, ctx);
    std::cout << "== PROGRAM ENDED ==" << endl;
    return 0;
}