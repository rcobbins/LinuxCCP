#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>

#define VOLDIR "/home/rob/ccp-controller/volumes/"
#define BASEFILEDIR "/home/rob/ccp-controller/config/"
#define BAP_CONFIG "basic_appprovider.conf"
#define VAULT_CONFIG "vault.ini"

char* itoa(int value, char* result, int base) {
  if (base < 2 || base > 36) { *result = '\0'; return result; }

  char* ptr = result, *ptr1 = result, tmp_char;
  int tmp_value;

  do {
    tmp_value = value;
    value /= base;
    *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
  } while ( value );

  if (tmp_value < 0) *ptr++ = '-';
    *ptr-- = '\0';
  while(ptr1 < ptr) {
    tmp_char = *ptr;
    *ptr--= *ptr1;
    *ptr1++ = tmp_char;
  }
  return result;
}

int create_instance(int num_instance) {
  char *instance_name;
  char *dir;
  char temp[4];

  itoa(num_instance, temp, 10);
  instance_name = malloc(14);
  strcpy(instance_name, "cybr_ccp_");
  for (int i=0; i<4-strlen(temp); i++)
    strcat(instance_name, "0");
  strcat(instance_name, temp);
  printf("Creating new instance %s!\n", instance_name);
  dir = malloc(strlen(VOLDIR) + strlen(instance_name) + 1);
  strcpy(dir, VOLDIR);
  strcat(dir, instance_name);
  mkdir(dir, 0700);
  char *tmp_dir = strdup(dir);
  tmp_dir = realloc(tmp_dir, strlen(tmp_dir) + strlen("/etcconf") + 1);
  strcat(tmp_dir, "/etcconf");
  mkdir(tmp_dir, 0700);
  char *cp_cmd = strdup("cp " BASEFILEDIR BAP_CONFIG " ");
  cp_cmd = realloc(cp_cmd, strlen(cp_cmd) + strlen(tmp_dir) + 1);
  strcat(cp_cmd, tmp_dir);
  system(cp_cmd);
  free(cp_cmd);
  free(tmp_dir);
  tmp_dir = NULL;
  tmp_dir = strdup(dir);
  tmp_dir = realloc(tmp_dir, strlen(tmp_dir) + strlen("/etcvault") + 1);
  strcat(tmp_dir, "/etcvault");
  mkdir(tmp_dir, 0700);
  cp_cmd = strdup("cp " BASEFILEDIR VAULT_CONFIG " ");
  cp_cmd = realloc(cp_cmd, strlen(cp_cmd) + strlen(tmp_dir) + 1);
  strcat(cp_cmd, tmp_dir);
  system(cp_cmd);
  free(cp_cmd);  
  free(tmp_dir);
  free(instance_name);
  free(dir);
  return 0;
}

int del_instance() {
  printf("Deleting most recently created instance!\n");

  return 0;
}

int main(int argc, char** argv) {
  char c = '\0';
  int num_instance = 0;
  static struct termios oldt, newt;
  tcgetattr( STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ICANON | ECHO);
  tcsetattr( STDIN_FILENO, TCSANOW, &newt);
  
  for (int i=0; i<atoi(argv[1]); i++) {
    ++num_instance;
    create_instance(num_instance);
  }

  while(c != '\n') {
    c = getchar();

    if (c == 'u') {
      ++num_instance;
      create_instance(num_instance);
    }
    if (c == 'd' && num_instance > 0) {     
      del_instance();
      num_instance--;
    }
  }
  tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

  for (int i=0; i<atoi(argv[0]); i++) {
    del_instance();
  }
  return 0;
}

