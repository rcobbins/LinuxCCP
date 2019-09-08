/*********************************************************
 * LinuxCCP.c
 * Web services wrapper to CyberArk Credential Provider
 * to broker access to applications via REST call
 * and process client-cert authentication
 *
 *********************************************************
 *
 * NOTE: Currently requires Shared Logon authentication to
 * PVWA API using incredibly privileged user (must have List 
 * Safe Members access for all Safes that require credentials
 * to be retrieved from and Audit Users authorization), due to 
 * the lack of PSDKWebserviceRequest method for any SDK that
 * is supported on a non-Windows server environment
 *
 *********************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <cyberark/cpasswordsdk.h>
#include <ulfius.h>

// TODO: Parameterize PORT, SERVICE_APPID and CYBR_PVWA via 
// configuration environment variables
#define PORT 9500
#define CYBR_PVWA "https://components.cyberarkdemo.com/PasswordVault/"
#define CYBR_SL_URI "WebServices/auth/Shared/RestfulAuthenticationService.svc/Logon"
#define CYBR_APP_URI "/WebServices/PIMServices.svc/Applications/"
#define CYBR_AUTH_METHOD_URI "/Authentications"
#define CYBR_ACCT_URI "api/Accounts?search="
#define CYBR_SAFE_URI "WebServices/PIMServices.svc/Safes/"
#define CYBR_SAFE_MEMBERS_URI "/Members"
#define SERVICE_APPID "ProvAuth"

/* 
 * Struct to track all Safes that Provider will have access to
 * and JSON objects containing the Safe's members and their level
 * of access to the Safe
 */
typedef struct {
  char *safe;
  int num_members;
  json_t **members;
} cybr_safe_members;

/* 
 * Struct to track all active Applications within the environment
 * and the available Authentication Methods that are attached to
 * each one
 */
typedef struct {
  char *appid;
  int num_methods;
  int num_serial;
  int num_certattr;
  int num_ip;
  json_t **serial;
  json_t **certattr;
  json_t **ip;
} cybr_auth_methods;

// Mutex variables for locking access to specific variables between main
// thread and maintenance threads running
pthread_mutex_t lock_auth;
pthread_mutex_t lock_num_request;
pthread_mutex_t lock_kill;

// Boolean value set to 1 when application ends. Used to
// kill authentication thread infinite loop
bool shutdown_app = false;

// Tracker for number of requests
int num_request = 0;

// Declare global variables for the Application Authentication
// methods and Safe Members, along with counter variables for  
// tracking the number of elements in each
int num_aml=0;
int num_sml=0;
cybr_safe_members *safe_members_list = NULL;
cybr_auth_methods *auth_methods_list = NULL;

/*
 * Utility function to read the contents of a file
 * into a string buffer, then return the string
 */
char *read_file(const char *filename) {
  char *buffer;
  long len;
  FILE *f = fopen(filename, "rb");
  if (f) {
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    buffer = malloc(len+1);
    if (buffer) {
      fread(buffer, 1, len, f);
      buffer[len] = '\0';
    }
    fclose(f);
  }
  return buffer;
}

/*
 * Utility function to convert binary values to the
 * corresponding hex value and return it as a string; Used by 
 * the certificate serial number extraction method
 */
static const char *bin2hex(const void *bin, size_t bin_size) {
        static char printable[110];
        const unsigned char *_bin = bin;
        char *print;
        size_t i;

        // Restrict the size of the binary to 50 bytes
        if (bin_size > 50)
                bin_size = 50;

        print = printable;
        // Loop through byte by byte and convert each byte
        // from binary to hex
        for (i = 0; i < bin_size; i++) {
                sprintf(print, "%.2x ", _bin[i]);
                print += 2;
        }

        return printable;
}

/*
 * Method to authenticate to CyberArk's PVWA API and return a
 * string containing the authentication token on successful
 * login
 */
char *cybr_api_sharedlogon() {
  char *token;
  struct _u_map headers;
  struct _u_request req;
  struct _u_response res;
  json_t *res_body;
  int err;

  // Define a map object containing HTTP request headers  
  u_map_init(&headers);
  u_map_put(&headers, "Content-Length", "0");
  u_map_put(&headers, "Content-Type", "application/json");

  // Initialize the HTTP request and populate with the appropriate
  // request data
  ulfius_init_request(&req);
  ulfius_set_empty_body_request(&req);
  req.http_verb = strdup("POST");
  req.http_url = strdup(CYBR_PVWA CYBR_SL_URI);
  req.check_server_certificate = 0;
  u_map_copy_into(req.map_header, &headers);

  // Initialize the HTTP response object and send HTTP request
  ulfius_init_response(&res);
  err = ulfius_send_http_request(&req, &res);
  if (err == U_OK) {
    // Populate the response JSON data into a variable, copy the
    // portion of the JSON object containing the "LogonResult" key
    // to a temporary JSON variable, and extract the token string
    // to be returned
    res_body = ulfius_get_json_body_response(&res, NULL);
    json_t *object = json_deep_copy(json_object_get(res_body, "LogonResult"));
    token = strdup(json_string_value(object));

    // Release all allocated memory prior to return
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);
    json_decref(res_body);
    json_decref(object);
    return token;
  }
  else {
    // Release all allocated memory prior to return
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);    
    return NULL;
  }
}
// TODO: Comment the rest of the PVWA function definitions....
// YOU KNOW WHAT THESE ALL DO!!!
json_t *cybr_api_get_apps(char *token) {
  struct _u_map headers;
  struct _u_request req;
  struct _u_response res;
  json_t *res_body;
  char *url;
  int err, url_len;

  // Define a map object containing HTTP request headers  
  u_map_init(&headers);
  u_map_put(&headers, "Content-Type", "application/json");
  u_map_put(&headers, "Authorization", token);

  // Allocate memory for the URL string
  url_len = strlen(CYBR_PVWA CYBR_APP_URI);
  url = malloc(url_len + 1);
  strcpy(url, CYBR_PVWA CYBR_APP_URI);

  ulfius_init_request(&req);
  ulfius_set_empty_body_request(&req);
  req.http_verb = strdup("GET");
  req.http_url = strdup(url);
  req.check_server_certificate = 0;
  u_map_copy_into(req.map_header, &headers);
  free(url);

  ulfius_init_response(&res);
  err = ulfius_send_http_request(&req, &res);
  if (err == U_OK) {
    if (res.status != 200) {
      ulfius_clean_request(&req);
      ulfius_clean_response(&res);
      u_map_clean(&headers);
      return NULL; 
    }
    res_body = ulfius_get_json_body_response(&res, NULL);
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);
    json_t *temp_body = json_deep_copy(json_object_get(res_body, "application"));
    json_decref(res_body);
    return temp_body;
  }
  else {
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);    
    return NULL;
  }
}

json_t *cybr_api_get_safes(char* token) {
  struct _u_map headers;
  struct _u_request req;
  struct _u_response res;
  json_t *res_body;
  char *url;
  int err, url_len;

  u_map_init(&headers);
  u_map_put(&headers, "Content-Type", "application/json");
  u_map_put(&headers, "Authorization", token);

  url_len = strlen(CYBR_PVWA CYBR_SAFE_URI);
  url = malloc(url_len + 1);
  strcpy(url, CYBR_PVWA CYBR_SAFE_URI);

  ulfius_init_request(&req);
  ulfius_set_empty_body_request(&req);
  req.http_verb = strdup("GET");
  req.http_url = strdup(url);
  req.check_server_certificate = 0;
  u_map_copy_into(req.map_header, &headers);
  free(url);

  ulfius_init_response(&res);
  err = ulfius_send_http_request(&req, &res);
  if (err == U_OK) {
    if (res.status != 200) {
      ulfius_clean_request(&req);
      ulfius_clean_response(&res);
      u_map_clean(&headers);
      return NULL; 
    }
    res_body = ulfius_get_json_body_response(&res, NULL);
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);
    json_t *temp_body = json_deep_copy(json_object_get(res_body, "GetSafesSlashResult"));
    json_decref(res_body);
    return temp_body;
  }
  else {
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);    
    return NULL;
  }
}

json_t *cybr_api_get_safe_members(char *token, char *safe_name) {
  struct _u_map headers;
  struct _u_request req;
  struct _u_response res;
  json_t *res_body;
  char *url;
  int err, url_len;

  u_map_init(&headers);
  u_map_put(&headers, "Content-Type", "application/json");
  u_map_put(&headers, "Authorization", token);

  url_len = strlen(CYBR_PVWA CYBR_SAFE_URI CYBR_SAFE_MEMBERS_URI) + strlen(safe_name);
  url = malloc(url_len + 1);
  strcpy(url, CYBR_PVWA CYBR_SAFE_URI);
  strcat(url, safe_name);
  strcat(url, CYBR_SAFE_MEMBERS_URI);

  ulfius_init_request(&req);
  ulfius_set_empty_body_request(&req);
  req.http_verb = strdup("GET");
  req.http_url = strdup(url);
  req.check_server_certificate = 0;
  u_map_copy_into(req.map_header, &headers);
  free(url);

  ulfius_init_response(&res);
  err = ulfius_send_http_request(&req, &res);
  if (err == U_OK) {
    if (res.status != 200) {
      ulfius_clean_request(&req);
      ulfius_clean_response(&res);
      u_map_clean(&headers);
      return NULL; 
    }
    res_body = ulfius_get_json_body_response(&res, NULL);
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);
    json_t *temp_body = json_deep_copy(json_object_get(res_body, "members"));
    json_decref(res_body);
    return temp_body;
  }
  else {
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);    
    return NULL;
  }
}

json_t *cybr_api_get_auth_methods(char *token, char *appid) {
  struct _u_map headers;
  struct _u_request req;
  struct _u_response res;
  json_t *res_body;
  char *url;
  int err, url_len;

  u_map_init(&headers);
  u_map_put(&headers, "Content-Type", "application/json");
  u_map_put(&headers, "Authorization", token);

  url_len = strlen(CYBR_PVWA CYBR_APP_URI CYBR_AUTH_METHOD_URI) + strlen(appid);
  url = malloc(url_len + 1);
  strcpy(url, CYBR_PVWA CYBR_APP_URI);
  strcat(url, appid);
  strcat(url, CYBR_AUTH_METHOD_URI);

  ulfius_init_request(&req);
  ulfius_set_empty_body_request(&req);
  req.http_verb = strdup("GET");
  req.http_url = strdup(url);
  req.check_server_certificate = 0;
  u_map_copy_into(req.map_header, &headers);
  free(url);

  ulfius_init_response(&res);
  err = ulfius_send_http_request(&req, &res);
  if (err == U_OK) {
    if (res.status != 200) {
      ulfius_clean_request(&req);
      ulfius_clean_response(&res);
      u_map_clean(&headers);
      return NULL; 
    }
    res_body = ulfius_get_json_body_response(&res, NULL);

    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);
    return res_body;
  }
  else {
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);    
    return NULL;
  }
}

json_t *cybr_api_get_account(char *token, char *account_object) {
  struct _u_map headers;
  struct _u_request req;
  struct _u_response res;
  json_t *res_body;
  char *url;
  int err, url_len;

  u_map_init(&headers);
  u_map_put(&headers, "Content-Type", "application/json");
  u_map_put(&headers, "Authorization", token);

  url_len = strlen(CYBR_PVWA CYBR_ACCT_URI) + strlen(account_object);
  url = malloc(url_len + 1);
  strcpy(url, CYBR_PVWA CYBR_ACCT_URI);
  strcat(url, account_object);

  ulfius_init_request(&req);
  ulfius_set_empty_body_request(&req);
  req.http_verb = strdup("GET");
  req.http_url = strdup(url);
  req.check_server_certificate = 0;
  u_map_copy_into(req.map_header, &headers);
  free(url);

  ulfius_init_response(&res);
  err = ulfius_send_http_request(&req, &res);
  if (err == U_OK) {
    if (res.status != 200) {
      ulfius_clean_request(&req);
      ulfius_clean_response(&res);
      u_map_clean(&headers);
      return NULL; 
    }
    res_body = ulfius_get_json_body_response(&res, NULL);
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);
    json_t *temp_body = json_deep_copy(json_object_get(res_body, "value"));
    json_t *temp_body2 = json_deep_copy(json_array_get(temp_body, 0));
    json_decref(res_body);
    json_decref(temp_body);
    return temp_body2;
  }
  else {
    ulfius_clean_request(&req);
    ulfius_clean_response(&res);
    u_map_clean(&headers);    
    return NULL;
  }
}

/*
 * Clean up all allocated resources associated with the
 * auth_methods_list
 */
void free_auth_methods_list() {
  for(int i=0; i<num_aml; i++) {
    free(auth_methods_list[i].appid);
    for(int j=0; j<auth_methods_list[i].num_ip; j++)
      json_decref(auth_methods_list[i].ip[j]);
    for(int j=0; j<auth_methods_list[i].num_serial; j++)
      json_decref(auth_methods_list[i].serial[j]);
    for(int j=0; j<auth_methods_list[i].num_certattr; j++)
      json_decref(auth_methods_list[i].certattr[j]);
    free(auth_methods_list[i].serial);
    free(auth_methods_list[i].certattr);
    free(auth_methods_list[i].ip);
  }
  free(auth_methods_list);
}

/*
 * Clean up all allocated resources associated with the
 * safe_members_list
 */
void free_safe_members_list() {
  for(int i=0; i<num_sml; i++) {
    free(safe_members_list[i].safe);
    for(int j=0; j<safe_members_list[i].num_members; j++)
      json_decref(safe_members_list[i].members[j]);
    free(safe_members_list[i].members);
  }
  free(safe_members_list);
}

void load_authentication() {
  char *token;
  json_t *applications, *account, *safes, *safe_members;
  cybr_safe_members *tmp_safe_members_list;
  cybr_auth_methods *tmp_auth_methods_list;
  int tmp_num_aml=0, tmp_num_sml=0;

  token = cybr_api_sharedlogon();
  if(token) {
    // Retrieve all AppIDs from the PVWA API
    applications = cybr_api_get_apps(token);
    if(applications) {
      // Allocate memory for the the new auth methods list and
      // get the number of AppIDs that were returned
      tmp_auth_methods_list = malloc(sizeof(cybr_auth_methods) * json_array_size(applications));
      tmp_num_aml = json_array_size(applications);
      for (int i=0; i<json_array_size(applications); i++) {
        // Initialize the various auth methods containers for the given AppID        
        tmp_auth_methods_list[i].num_certattr = 0;
        tmp_auth_methods_list[i].certattr = NULL;
        tmp_auth_methods_list[i].num_serial = 0;
        tmp_auth_methods_list[i].serial = NULL;
        tmp_auth_methods_list[i].num_ip = 0;
        tmp_auth_methods_list[i].ip = NULL;
        tmp_auth_methods_list[i].appid = strdup(json_string_value(json_object_get(json_array_get(applications, i), "AppID")));
        // Retrieve the authentication methods for the AppID from the PVWA API
        // and copy the inner object within the "authentication" key
        json_t* temp_methods = cybr_api_get_auth_methods(token, tmp_auth_methods_list[i].appid);
        json_t* auth_methods = json_deep_copy(json_object_get(temp_methods, "authentication"));
        json_decref(temp_methods);
        tmp_auth_methods_list[i].num_methods = json_array_size(auth_methods);
        if (tmp_auth_methods_list[i].num_methods > 0) {
          for (int j=0; j<tmp_auth_methods_list[i].num_methods; j++) {
            // Check if the given auth method is a serial number, and
            // handle the appropriate logic to store a serial number type
            // auth method
            if (!strcmp(json_string_value(json_object_get(json_array_get(auth_methods, j), "AuthType")), "certificateSerialNumber")) {
              tmp_auth_methods_list[i].num_serial++;
              tmp_auth_methods_list[i].serial = realloc(tmp_auth_methods_list[i].serial, sizeof(json_t) * tmp_auth_methods_list[i].num_serial);
              tmp_auth_methods_list[i].serial[tmp_auth_methods_list[i].num_serial-1] = json_deep_copy(json_array_get(auth_methods, j));
            }
            // Check if the given auth method is an IP address, and
            // handle the appropriate logic to store an IP address type
            // auth method            
            else if (!strcmp(json_string_value(json_object_get(json_array_get(auth_methods, j), "AuthType")), "machineAddress")) {
              tmp_auth_methods_list[i].num_ip++;
              tmp_auth_methods_list[i].ip = realloc(tmp_auth_methods_list[i].ip, sizeof(json_t) * tmp_auth_methods_list[i].num_ip);
              tmp_auth_methods_list[i].ip[tmp_auth_methods_list[i].num_ip-1] = json_deep_copy(json_array_get(auth_methods, j));
            }
            // Check if the given auth method is a certificate attribute
            // (Subject, Issuer, SAN), and handle the appropriate logic
            // to store a serial number type auth method
            else if (!strcmp(json_string_value(json_object_get(json_array_get(auth_methods, j), "AuthType")), "certificateattr")) {
              tmp_auth_methods_list[i].num_certattr++;
              tmp_auth_methods_list[i].certattr = realloc(tmp_auth_methods_list[i].certattr, sizeof(json_t) * tmp_auth_methods_list[i].num_certattr);
              tmp_auth_methods_list[i].certattr[tmp_auth_methods_list[i].num_certattr-1] = json_deep_copy(json_array_get(auth_methods, j));
            }
          } 
        }
        json_decref(auth_methods);
      }
      json_decref(applications);
      // Lock the auth_methods_list variable if it is already populated
      // so that it cannot be accessed by another thread, free the already
      // allocated auth_method_list, and point it to the newly allocated
      // auth_method_list
      pthread_mutex_lock(&lock_auth);
      if (auth_methods_list != NULL) {
        free_auth_methods_list();
        auth_methods_list = NULL;
      }
      num_aml = tmp_num_aml;        
      auth_methods_list = tmp_auth_methods_list;
      tmp_auth_methods_list = NULL;
      pthread_mutex_unlock(&lock_auth);
    }
    // Retrieve all Safes from the PVWA API
    safes = cybr_api_get_safes(token);
    if(safes) {
      // Allocate memory for the safe_members_list based on the number of Safes returned
      tmp_safe_members_list = malloc(sizeof(cybr_safe_members) * json_array_size(safes));
      tmp_num_sml = json_array_size(safes);
      for(int i=0; i<json_array_size(safes); i++) {
        // Copy Safe name into safe member list struct
        tmp_safe_members_list[i].safe = strdup(json_string_value(json_object_get(json_array_get(safes, i), "SafeName")));
        // Retrieve all Safe Members for a given Safe from PVWA API
        safe_members = cybr_api_get_safe_members(token, tmp_safe_members_list[i].safe);
        tmp_safe_members_list[i].num_members = json_array_size(safe_members);
        if (tmp_safe_members_list[i].num_members > 0) {
          // Allocate memory for the Safe Members and copy each member into the structure
          tmp_safe_members_list[i].members = malloc(sizeof(json_t) * tmp_safe_members_list[i].num_members);
          for (int j=0; j<tmp_safe_members_list[i].num_members; j++) {
            tmp_safe_members_list[i].members[j] = json_deep_copy(json_array_get(safe_members, j));
          }
        }
        json_decref(safe_members);
      }
      json_decref(safes);
      // Lock the safe_members_list variable if it is already populated
      // so that it cannot be accessed by another thread, free the already
      // allocated safe_members_list, and point it to the newly allocated
      // safe_members_list      
      pthread_mutex_lock(&lock_auth);
      if (safe_members_list != NULL) {
        free_safe_members_list();
        safe_members_list = NULL;
      }
      num_sml = tmp_num_sml;
      safe_members_list = tmp_safe_members_list;
      tmp_safe_members_list = NULL;
      pthread_mutex_unlock(&lock_auth);
    }
    free(token);
  }
}

/*
 * Thread function that is used to periodically update
 * the loaded safe members list authentication methods
 * for the AppIDs that are available
 */
void *load_auth_thread_loop() {
  bool temp = 0;
  // Loop until the application has been killed
  // Sleep for 60 seconds, then reload the authentication
  // methods
  while (!temp) {
    // Wait for one minute
    sleep(60);
    load_authentication();
    // Lock the shutdown_app variable, so that it cannot be overwritten
    // Copy it to temp
    pthread_mutex_lock(&lock_kill);
    temp = shutdown_app;
    pthread_mutex_unlock(&lock_kill);
  }
}

/*
 * Utility function to convert a CIDR bitmask
 * to its corresponding netmask string and return it
 */
char *cidr_to_netmask(char *cidr) {
  uint32_t i_netmask;
  struct in_addr netmask;
  char *end;
  int i_cidr = strtol(cidr, &end, 10);

  i_netmask = 0xFFFFFFFF;
  if (i_cidr < 32)
    i_netmask <<= 32 - i_cidr;
  i_netmask = htnol(i_netmask);
  netmask.s_addr = i_netmask;

  return inet_ntoa(netmask);
}

/***
 * Return variable containing contents of file
 */


/*
 * Function to process the provided AppID's allowed authentication
 * methods and Safe membership ACLs to determine if it is allowed
 * to retrieve the requested password object. Returns non-zero if
 * successful.
 */
bool validate_appid_access(char *appid, char* safename, struct sockaddr *client_address, gnutls_x509_crt_t client_cert) {
  // Extract IP address from provided socket object
  struct sockaddr_in *address = (struct sockaddr_in *)client_address;
  char *ip_address = strdup(inet_ntoa(address->sin_addr));

  char serial[40];
  size_t size;
  gnutls_x509_subject_alt_name_t *san;
  size_t san_size=0;
  int app_index=-1;
  int res;
  bool valid=true;

  // Locate the provided AppID in the pre-loaded list of
  // authentication methods
  for (int i=0; i<num_aml; i++) {
    if(!strcmp(auth_methods_list[i].appid, appid)) {
      app_index=i;
      break;
    }
  }

  // If there are any authentication methods for the provided AppID
  // for Allowed Machines, loop through all allowed IP address and CIDR
  // ranges to determine if the requestor address matches any
  if (auth_methods_list[app_index].num_ip > 0) {
    bool ipfound=false;

    for(int i=0; i<auth_methods_list[app_index].num_ip; i++) {
      // Extract the address or CIDR range from the JSON object
      char *ip_auth = strdup(json_string_value(json_object_get(auth_methods_list[app_index].ip[i], "AuthValue")));
      char *saveptr = NULL;
      
      // Check if there is a CIDR range, and if so isolate the bitmask from the network address
      char* cidr = strtok_r(ip_auth, "/", &saveptr);
      // No CIDR range, so the extracted value is an IP address
      if(!strcmp(saveptr, "")) {
        if(!strcmp(ip_auth, ip_address)) {
          ipfound=true;
          break;
        }
      }
      else {
        // Convert the CIDR bitmask to a full IP netmask
        struct in_addr netmask_ip, network_ip, requestor_ip;
        ip_auth = strdup(cidr);
        inet_aton(ip_auth, &network_ip);
        cidr = strtok_r(NULL, "/", &saveptr);
        inet_aton(cidr_to_netmask(cidr), &netmask_ip);
        inet_aton(ip_address, &requestor_ip);
        // Verify that the requestor IP address falls within the network address
        if((requestor_ip.s_addr & netmask_ip.s_addr) == (network_ip.s_addr & netmask_ip.s_addr)) {
          ipfound=true;
          break;
        }
      }
    }
    if(!ipfound)
      valid = false;
  }

  // Extract the serial number from the presented mTLS certificate
  size = sizeof(serial);
  gnutls_x509_crt_get_serial(client_cert, serial, &size);

  // Check if any of the authentication methods for the AppID use
  // certificate serial numbers, and if so extract the serial number
  // from the JSON object and validate against the presented mTLS certificate's
  // serial number
  if (auth_methods_list[app_index].num_serial > 0) {
    bool serialfound = false;
    for (int i=0; i<auth_methods_list[app_index].num_serial; i++) {
      char *serial_number = strdup(json_string_value(json_object_get(auth_methods_list[app_index].serial[i], "AuthValue")));

      if(!strcmp(bin2hex(serial, size), serial_number)) {
        serialfound = true;
        break;
      }
    }
    if(!serialfound)
      valid = false;
  }

  // Locate the index of the Safe Member's list for the Safe
  // that matches the requested passwords object's Safe
  for (int i=0; i<num_sml; i++) {
    if(!strcmp(safe_members_list[i].safe, safename)) {
      app_index = i;
      break;
    }
  }
  
  // Ensure there is at least one Safe Member for this Safe, then
  // validate that the AppID user has been added to the Safe
  if (safe_members_list[app_index].num_members > 0) {   
    bool safematch = false;
    for (int i=0; i<safe_members_list[app_index].num_members; i++) {
      if (!strcmp(json_string_value(json_object_get(safe_members_list[app_index].members[i], "UserName")), appid))
        safematch = true;
    } 
  }

  // TODO: Check for and validate SAN, Issuer, and Subject authentication methods
  /*do {
    res = gnutls_x509_crt_get_subject_alt_name (client_cert, i, san, &san_size, NULL);
    if (res == GNUTLS_E_SHORT_MEMORY_BUFFER) {
      san = malloc(san_size+1);
      res = gnutls_x509_crt_get_subject_alt_name (client_cert, i, san, &san_size, NULL);
    }

    if (res == GNUTLS_SAN_IPADDRESS) {
      struct in_addr addr;
      char *temp = malloc(san_size + 1);
      char *temp2 = malloc(san_size+1);
      strncpy(temp, (char*) san, san_size);  
      for (int j=0; j<san_size; j++) {
        temp2[j] = temp[san_size-j-1];
      }
      memcpy(san, temp2, san_size);
      addr.s_addr = htonl((unsigned int) *san);
      printf("%s\n", inet_ntoa(addr));
    }
    else if (res == GNUTLS_SAN_DNSNAME || res == GNUTLS_SAN_URI || res == GNUTLS_SAN_RFC822NAME)
      printf("%s\n", (char*)san);  
    i++;
  } while(res != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);*/

  free(ip_address);

  return valid;
}

/**
 * Using CyberArk's C Password SDK for AAM CP, retrieve
 * the requested password object. Store the request credential
 * and additional properties in a JSON object that will be returned
 * to the caller.
 */
json_t *get_password(char *query) {
  json_t *response = json_object();
  ObjectHandle psdkResponse = NULL;
  ObjectHandle psdkRequest = NULL;
  char **pVals = NULL;
  int err = 0;

  // Create a new password request
  psdkRequest = PSDK_CreateRequest("PASSWORD");
  if(psdkRequest != NULL) {
    // Set request AppID, and appropriate error handling
    err = PSDK_SetAttribute(psdkRequest, "AppDescs.AppID", "ProvAuth");
    if (err == PSDK_RC_ERROR) {
      printf("Error setting AppID\n");
      printf("Error Code: %d - %s\n", PSDK_GetErrorCode(psdkRequest), PSDK_GetErrorMsg(psdkRequest));
      PSDK_ReleaseHandle(&psdkRequest);
      return NULL;
    }
    //// Set request Query, and appropriate error handling
    err = PSDK_SetAttribute(psdkRequest, "Query", query);
    if (err == PSDK_RC_ERROR) {
      printf("Error setting query\n");
      printf("Error Code: %d - %s\n", PSDK_GetErrorCode(psdkRequest), PSDK_GetErrorMsg(psdkRequest));
      PSDK_ReleaseHandle(&psdkRequest);
      return NULL;
    }
    // Attempt to get the password from the CP
    err = PSDK_GetPassword(psdkRequest, &psdkResponse);
    if (err == PSDK_RC_ERROR) {
      printf("Error retrieving password\n");
      printf("Error Code: %d - %s", PSDK_GetErrorCode(psdkRequest), PSDK_GetErrorMsg(psdkRequest));
      PSDK_ReleaseHandle(&psdkRequest);
      return NULL;
    }
    else {
      // Retrieve the password value, and return an error if the password is unable to be retrieved.
      // Set the response object with the key/value pair for the password
      pVals = PSDK_GetAttribute(psdkResponse, "Password");
      if (pVals) {
        json_object_set_new(response, "Password", json_pack("s", pVals[0]));
	      PSDK_ReleaseAttributeData(&pVals);
      }
      else
        printf("Error Code: %d - %s", PSDK_GetErrorCode(psdkResponse), PSDK_GetErrorMsg(psdkResponse));

      // Return the additional password properties for the requested object, if they exist
      // Sets appropriate key/values for the retrieved properties in the response object
      pVals = PSDK_GetAttribute(psdkResponse, "PassProps.UserName");
      if (pVals) {
        json_object_set_new(response, "UserName", json_pack("s", pVals[0]));
        PSDK_ReleaseAttributeData(&pVals);
      }
      pVals = PSDK_GetAttribute(psdkResponse, "PassProps.Address");
      if (pVals) {
        json_object_set_new(response, "Address", json_pack("s", pVals[0]));
        PSDK_ReleaseAttributeData(&pVals);
      }
      pVals = PSDK_GetAttribute(psdkResponse, "PassProps.Database");
      if (pVals) {
        json_object_set_new(response, "Database", json_pack("b", pVals[0]));
        PSDK_ReleaseAttributeData(&pVals);
      }
      pVals = PSDK_GetAttribute(psdkResponse, "PasswordChangeInProcess");
      if (pVals) {
        bool pwdChange;
	      if (!strncmp(pVals[0], "true", strlen(pVals[0])))
	        pwdChange = true;
	      else
	        pwdChange = false;
        json_object_set_new(response, "PasswordChangeInProcess", json_pack("b", pwdChange));
        PSDK_ReleaseAttributeData(&pVals);
      }
    }
  }
  if(psdkRequest)
    PSDK_ReleaseHandle(&psdkRequest);
  if(psdkResponse)
    PSDK_ReleaseHandle(&psdkResponse);

  return response;
}

/**
 * Callback function for the web application on /HTTPUsage url call
 */
int c_http_usage(const struct _u_request * request, struct _u_response * response, void * user_data) {
  int temp;
  char str[20];

  // Lock num_request, assign value to a temporary variable, and reset to 0
  pthread_mutex_lock(&lock_num_request);
  temp=num_request;
  num_request=0;
  pthread_mutex_unlock(&lock_num_request);

  // Convert the number of requests to a string and then pass as the HTTP response
  sprintf(str, "%d", temp);
  ulfius_set_string_body_response(response, 403, str);

  return U_CALLBACK_CONTINUE;
}

/**
 * Callback function for the web application on /GetPassword url call
 */
int c_get_password (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t *body = ulfius_get_json_body_request(request, NULL);
  json_t *appid, *data, *query, *query_fmt, *object, *safe, *folder, *username, 
	 *address, *database, *policy_id, *timeout, *fail_on_change, *password;
  char *str_query, *str_query_fmt = NULL, *str_appid, *temp, *safename=NULL;
  
  // Lock and increment total HTTP request count
  pthread_mutex_lock(&lock_num_request);
  ++num_request;
  pthread_mutex_unlock(&lock_num_request);

  // Initialize str_query as an empty null-terminated string
  str_query = malloc(1);
  strcpy(str_query, "");

  // Attempt to get App ID from request JSON, and validate that it actually exists
  // Return error if it is not presented, otherwise copy it to a string variable
  appid = json_object_get(body, "appId");
  if (!json_is_string(appid)) {
    ulfius_set_string_body_response(response, 400, "appId required");
    json_decref(body);
    return U_CALLBACK_CONTINUE;
  }
  str_appid = malloc(strlen(json_string_value(appid)) + 1);
  strcpy(str_appid, json_string_value(appid));
  

  // Attempt to get data JSON object from request JSON, throw error if it does not exist
  data = json_object_get(body, "data");
  if (!json_is_object(data)) {
    ulfius_set_string_body_response(response, 400, "Request Message content is invalid");
    json_decref(body);
    return U_CALLBACK_CONTINUE;
  }

  // If "Query" key was sent in data, set query to that string and ignore everything else
  query = json_object_get(data, "Query");
  if (query && json_is_string(query)) {
    str_query = malloc(strlen(json_string_value(query)) + 1);
    strcpy(str_query, json_string_value(query));

    // Check to see if a format for the query was set
    // Default is for exact, so only testing for regex
    // Only needs to be done in the event that 
    query_fmt = json_object_get(data, "QueryFormat");
    if (query_fmt && json_is_string(query_fmt)) {
      if(!strcmp(json_string_value(query_fmt), "Regexp")) {
        str_query_fmt = malloc(7);
	      strcpy(str_query_fmt, "Regexp");
      }
    }

    // Look for a Safe name in the query (to be used to validate AppID safe membership)
    // If Safe name is found, store it to be used 
    char *safelocate, *saveptr;
    safelocate=strtok_r(str_query, ";", &saveptr);
    while(safelocate != NULL) {
      if(strstr(safelocate, "Safe"))
        break;
    }
    if(safelocate) {
      char *temp = strtok_r(safelocate, "=", &saveptr);
      safename = strdup(saveptr);
    }
    else
      ulfius_set_string_body_response(response, 400, "Safe is a required query parameter\n\n");
  }
  // If no query string passed in request, check for other properties to create query
  else {
    // Check for "Object" key, and if it exists append the value to the query string
    object = json_object_get(data, "Object");
    if (object && json_is_string(object)) {
      temp = malloc(strlen(json_string_value(object)) + 10);
      strcpy(temp, "Object=");
      strcat(temp, json_string_value(object));
      strcat(temp, ";");
      str_query = realloc(str_query, strlen(str_query) + strlen(temp) + 1);
      strcat(str_query, temp);
      free(temp);

    }

    // Check for "Safe" key, and if it exists append the value to the query string
    safe = json_object_get(data, "Safe");
    if (safe && json_is_string(safe)) {
      temp = malloc(strlen(json_string_value(safe)) + 7);
      safename = strdup(json_string_value(safe));
      strcpy(temp, "Safe=");
      strcat(temp, json_string_value(safe));
      strcat(temp, ";");
      str_query = realloc(str_query, strlen(str_query) + strlen(temp) + 1);
      strcat(str_query, temp);
      free(temp);
    }

    // Check for "Folder" key, and if it exists append the value to the query string
    folder = json_object_get(data, "Folder");
    if (folder && json_is_string(folder)) {
      temp = malloc(strlen(json_string_value(folder)) + 9);
      strcpy(temp, "Folder=");
      strcat(temp, json_string_value(folder));
      strcat(temp, ";");
      str_query = realloc(str_query, strlen(str_query) + strlen(temp) + 1);
      strcat(str_query, temp);
      free(temp);
    }
  }
  // If no valid safe name, set appropriate response
  if(!safename)
    ulfius_set_string_body_response(response, 400, "Safe is a required query parameter\n\n");
  else {
    // Validate that the AppID used has appropriate access to the password that has been requested
    bool valid_appid = false;
    pthread_mutex_lock(&lock_auth);    
    valid_appid = validate_appid_access(str_appid, safename, request->client_address, request->client_cert);
    pthread_mutex_unlock(&lock_auth);
    if (valid_appid) {
      // If query string was successfully created, get password
      if (str_query) {
        str_query[strlen(str_query)-1] = '\0';
        password = get_password(str_query);
        /***
        * TODO: Add error handling for get_password
        */
      }
      /***
      * TODO: Add error handling for string query
      */
      // Set appropriate response based on the conditions of the 
      if (password)
        ulfius_set_json_body_response(response, 200, password);
      else
        ulfius_set_string_body_response(response, 400, "Password unretrievable with specified parameters\n\n");
    }
    else
      ulfius_set_string_body_response(response, 403, "FORBIDDEN\n\n");
  }

  // Cleanup allocated resources prior to returning
  json_decref(body);
  json_decref(password);
  free(safename);
  free(str_query);
  free(str_appid);

  return U_CALLBACK_CONTINUE;
}

/**
 * main function
 */
int main(int argc, char **argv) {
  struct _u_instance instance;
  char *server_key = read_file(argv[1]), *server_pem = read_file(argv[2]), *root_ca_pem = read_file(argv[3]);
  pthread_t auth_thread;
  void *status;

  // Initialize mutexes for use in threads
  pthread_mutex_init(&lock_auth, NULL);
  pthread_mutex_init(&lock_num_request, NULL);
  pthread_mutex_init(&lock_kill, NULL);

  // Initially pre-load all the authentication methods 
  load_authentication();

  // Initialize instance with the port number
  if (ulfius_init_instance(&instance, PORT, NULL, NULL) != U_OK) {
    fprintf(stderr, "Error ulfius_init_instance, abort\n");
    return(1);
  }

  // Endpoint list declaration
  ulfius_add_endpoint_by_val(&instance, "POST", "/GetPassword", NULL, 0, &c_get_password, NULL);
  ulfius_add_endpoint_by_val(&instance, "GET", "/HTTPUsage", NULL, 0, &c_http_usage, NULL);

  // Start the framework
  int err = ulfius_start_secure_ca_trust_framework(&instance, server_key, server_pem, root_ca_pem);

  if(err == U_OK) {
    pthread_create(&auth_thread, NULL, load_auth_thread_loop, NULL);
    printf("Start framework on port %d\n", instance.port);
    free(server_pem);
    free(server_key);
    free(root_ca_pem);

    // Wait for the user to press <enter> on the console to quit the application
    getchar();

    // Update the app shutdown toggle so that the while loop in the authentication
    // method update loop can be terminated cleanly
    pthread_mutex_lock(&lock_kill);
    shutdown_app = 1;
    pthread_mutex_unlock(&lock_kill);
    // Before exiting release all allocated memory for the preloaded authentication
    // methods and safe member ACLs
    free_auth_methods_list();
    free_safe_members_list();

    // Clean up all the dangling threads and mutex allocations
    pthread_join(auth_thread, &status);
    pthread_mutex_destroy(&lock_auth);
    pthread_mutex_destroy(&lock_num_request);
    pthread_mutex_destroy(&lock_kill);
  }
  else {
    printf("%d\n", err);
    fprintf(stderr, "Error starting framework\n");
  }
  printf("End framework\n");
  pthread_exit(NULL);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);

  return 0;
}