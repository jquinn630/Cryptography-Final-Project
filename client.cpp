#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <err.h>

//OpenSSL for Encryption
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "packet_structs.h"
#include "crypto_lib.h"

void print_options()
{
  printf("Here is a list of available commands.\n\t h - list help menu\n\t a - view accounts information\n\t p - view personal profile information\n\t t - transfer funds between two accounts\n\t i - change personal profile information\n\t l - view transaction log\n\t q - quit application\n");
}

void print_options_admin()
{
  printf("Here is a list of available commands.\n\t h - list help menu\n\t v - view all accounts for a user\n\t c - create a new account \n\t u - create a new user \n\t a - add funds to an account\n\t r - remove funds from an account \n\t q - quit application\n");
}

void clear_send_buff(unsigned char * sendBuf)
{
  for (int i=0; i<256; i++)
  {
    sendBuf[i]=0x0;
  }
}

void print_user_info(struct user_info * current_user)
{
  printf("User: %s\n", (*current_user).uname);
  printf("Name: %s %s\n", (*current_user).first, (*current_user).last);
  printf("Email: %s\n", (*current_user).email);
  printf("Telephone: %s\n", (*current_user).telephone);
}

void print_accounts_info(struct all_accounts *user_accounts)
{
  int i;
  for (i=0; i<(*user_accounts).num_accounts; i++)
  {
    struct accounts current_account = (*user_accounts).account_list[i];
    printf("Account no: %s ", current_account.accountno);
    if (current_account.type == 0)
    {
      printf("Savings ");
    }
    else if (current_account.type == 1)
    {
      printf("Checking ");
    }
    printf("Balance: %d\n",current_account.funds);
  }
}

void print_transfer_info(struct all_transfers *transfers)
{
  int i; 
  printf("Here are your most recent transfers (up to 8): \n");
  for (i=0; i<(*transfers).num_transfers; i++)
  {
    struct transfer current_transfer = (*transfers).transfer_list[i];
    printf("From: %s   To: %s   Amount: %d   Time: %s\n", current_transfer.sender, current_transfer.receiver, current_transfer.amount, current_transfer.date);
  }
}

int do_request_reply(int sockfd, unsigned char * sendBuf, unsigned char * recBuf, unsigned char * theKey, unsigned char * hashKey)
{
  unsigned char encSendBuf[256];
  unsigned char encRecBuf[1024];

  unsigned char iv[32];

  gen_iv(iv);

  memcpy(encSendBuf+200, iv, 32);

  unsigned char hashVal[32];

  aes_cbc_sec_enc(sendBuf, encSendBuf, 160, theKey, iv);

  compute_hash(encSendBuf, 160, hashVal, hashKey);
  memcpy(encSendBuf+160, hashVal, 32);

  if(send(sockfd, encSendBuf, 256, 0)==-1)
  {
    printf("An error occurred sending the server request info.");
    return -1;
  }

  if(recv(sockfd, encRecBuf, 1024, 0)==-1)
  {
    printf("Error occurred receiving the server response.");
    return -1;
  }

  memcpy(iv, encRecBuf+960, 32);

  memcpy(hashVal, encRecBuf+928, 32);
  if (verify_hash(encRecBuf, 928, hashVal, hashKey)==0)
  {
    printf("WARNING: HMAC not verified.  Data may be tampered with.\n");
  }

  aes_cbc_sec_dec(encRecBuf, recBuf, 928, theKey, iv);

  return 0;
}

int check_authentication(int sockfd)
{
    int authenticate=0;
    char name[64];
    char password[64];
    struct user_pass log_attempt;
    struct user_pass enc_log_attempt;

    //prompt user for password
    printf("Enter usename:");
    scanf("%s", name);
    printf("Enter password:");
    scanf("%s", password);

    //copy into struct
    strncpy(log_attempt.name, name, strlen(name));
    strncpy(log_attempt.pass, password, strlen(password));

    // NULL termintate strings
    log_attempt.name[strlen(name)]='\0';
    log_attempt.pass[strlen(password)]='\0';

    // get the RSA public key
    RSA *serverkey = RSA_new();
    FILE * publicKeyOut = fopen("pubkey.pem", "r");
    PEM_read_RSAPublicKey(publicKeyOut, &serverkey, NULL, NULL);
    fclose(publicKeyOut);

    if(RSA_public_encrypt(64, (unsigned char*)&log_attempt.name, (unsigned char*)&enc_log_attempt.name, serverkey, RSA_NO_PADDING)==-1)
    {
      char err[64];
      ERR_load_crypto_strings();
      ERR_error_string(ERR_get_error(), err);
      fprintf(stderr, "Error encrypting message: %s\n", err);
    }
    if(RSA_public_encrypt(64, (unsigned char*)&log_attempt.pass, (unsigned char*)&enc_log_attempt.pass, serverkey, RSA_NO_PADDING)==-1)
    {
      char err[64];
      ERR_load_crypto_strings();
      ERR_error_string(ERR_get_error(), err);
      fprintf(stderr, "Error encrypting message: %s\n", err);
    }

    // send packet of uname/pass
    if(send(sockfd, &enc_log_attempt, sizeof(struct user_pass), 0)==-1)
    {
      printf("An error occurred sending the login info.");
      return 0;
    }

    // check authentication
    if(recv(sockfd, &authenticate, sizeof(int), 0)==-1)
    {
      printf("Error occurred with authentication response.");
      return 0;
    }
    //give user response  
    if(authenticate==0)
    {
      printf("Username/password combination not recognized.  Please try again. \n");
    }
    else
    {
      printf("Authentication succeeded.  Welcome %s.\n", log_attempt.name);
    }

    return authenticate;
}
 
int main(void)
{
  int sockfd = 0;
  struct sockaddr_in serv_addr;

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0))< 0)
  {
    printf("\n Error : Could not create socket \n");
    return 1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(5000);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0)
  {
    printf("\n Error : Connect Failed \n");
    return 1;
  }
 
  int authenticate = 0; 
  int isAdmin;

  // get Public RSA key from server
  authenticate=check_authentication(sockfd);
  if (authenticate==0)
  {
    return 0;
  }

  // check for admin privileges
  if(recv(sockfd, &isAdmin, sizeof(int), 0)==-1)
  {
    printf("Error occurred with admin info response.");
    return 0;
  }

  // after we authenticated, loop to accept commands
  if (authenticate==1)
  {
    char input[8];
    fgets(input, 8, stdin);
    unsigned char sendBuf[256];
    unsigned char recBuf[1024];

    unsigned char theKey[32];
    unsigned char hashKey[32];

    printf("Generating shared secret...\n");

    // set up shared secret key using Diffie Hellman
    // setup p and g
    if(recv(sockfd, recBuf, 1024, 0)==-1)
    {
      printf("Error occurred with authentication response.");
      return 0;
    }

    unsigned char serverPublicKey[128];
    unsigned char P[128];
    unsigned char G[1];
    unsigned char publicKey[128];

    memcpy(P, recBuf, 128);
    memcpy(serverPublicKey, recBuf+128, 128);
    memcpy(G, recBuf+256, 1);

    DH *privkey=DH_new(); 

    privkey->p = BN_new();
    privkey->g = BN_new();

    BN_bin2bn(G, 1, privkey->g);
    BN_bin2bn(P, 128, privkey->p);

    if(DH_generate_key(privkey))
    {
      BN_bn2bin(privkey->pub_key, publicKey);
    }

    memcpy(sendBuf, publicKey, 128);

    if(send(sockfd, sendBuf, 256, 0)==-1)
    {
      printf("An error occurred sending the request to the client.");
      return -1;
    }

    BIGNUM * pubKeyBN = BN_new();
    BN_bin2bn(serverPublicKey, 128, pubKeyBN);

    unsigned char sharedKey[128];
    DH_compute_key(sharedKey, pubKeyBN, privkey);

    memcpy(theKey, sharedKey, 32);

    unsigned char encRecBuf[1024];
    if(recv(sockfd, encRecBuf, 1024, 0)==-1)
    {
      printf("Error occurred receiving the server response.");
      return -1;
    }  

    unsigned char iv[32];
    memcpy(iv, encRecBuf+960, 32);
    aes_cbc_sec_dec(encRecBuf, recBuf, 928, theKey, iv);

    memcpy(hashKey, recBuf, 32);

    printf("Enter 'h' to list options.");

    if (isAdmin==0)
    {
      while(1)
      {
        clear_send_buff(sendBuf);
        printf("\nPlease enter a command:"); 
        fgets(input, 8, stdin);
        if (input[0]=='\n')
        {
          continue;
        }
        if (input[0]=='h')
        {
          // help menu
          print_options();
        }
        else if (input[0]=='a')
        {
          // view accounts of user
          sendBuf[0]='a';

          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;

          struct all_accounts * user_accounts;
          user_accounts = (struct all_accounts *) recBuf;
          printf("NUMBER OF ACCOUNTS %d\n", (*user_accounts).num_accounts);
          print_accounts_info(user_accounts);

        }
        else if (input[0]=='p')
        {
          // lets user view their personal information
          sendBuf[0]='p';

          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;

          struct user_info * current_user;
          current_user = (struct user_info *) recBuf;
          print_user_info(current_user);

        }
        else if (input[0]=='t')
        {
          // lets user transfer funds between their own accounts
          sendBuf[0]='t';

          struct transfer current_transfer;
          printf("Account Transer:\nYou must own the sending account.\nPlease enter account no. of sending account:\n");
          fgets(current_transfer.sender, 30, stdin);
          if (current_transfer.sender[strlen(current_transfer.sender)-1]=='\n') current_transfer.sender[strlen(current_transfer.sender)-1]='\0';
          printf("Please enter account no. of receiving account: \n");
          fgets(current_transfer.receiver, 30, stdin);
          if (current_transfer.receiver[strlen(current_transfer.receiver)-1]=='\n') current_transfer.receiver[strlen(current_transfer.receiver)-1]='\0';
          fflush(stdin);
          printf("Please enter the amount you would like to transfer: \n");
          scanf("%d", &current_transfer.amount);
          fflush(stdin);

          memcpy(sendBuf+1, &current_transfer, sizeof(struct transfer));
          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;

          char result[128];
          memcpy(result, recBuf, 128);
          printf("%s\n", result);
        }
        else if (input[0]=='i')
        {
          // lets user change their personal information
       	  sendBuf[0]='i';
          char change[8];
          printf("Enter a choice:\n\t e - change email \n\t t - change telephone\n\t q - cancel request\n:");
          fgets(change, 8, stdin);
          // do choice
          char new_entry[64];
          if (change[0]=='e')
          {
          	sendBuf[1]='e';
          	printf("Please enter a new email: \n");
          	fgets(new_entry, 64, stdin);
            if (new_entry[strlen(new_entry)-1]=='\n') new_entry[strlen(new_entry)-1]='\0';
          	memcpy(sendBuf+2, new_entry, 64);
            if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;
            else printf("Email changed.\n");
          }
          else if (change[0]=='t')
          {
          	sendBuf[1]='t';
          	printf("Please enter a new phone number: \n");
          	fgets(new_entry, 64, stdin);
            if (new_entry[strlen(new_entry)-1]=='\n') new_entry[strlen(new_entry)-1]='\0';
          	memcpy(sendBuf+2, new_entry, 64);
          	if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;
          	else printf("Telephone changed.\n");
          }
          else if (change[0]=='q')
          {
          	continue;
          }
          else
          {
            printf("Error: invalid choice.");
            continue;
          }
        }
        else if (input[0]=='l')
        {
          // lets user view a log of their past transactions
          sendBuf[0]='l';

          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;

          struct all_transfers * transfers;
          transfers = (struct all_transfers *) recBuf;
          print_transfer_info(transfers);
        }
        else if (input[0]=='q')
        {
          // exits the applications safely, closing connection with server
          sendBuf[0]='q';
          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;
          else printf("Goodbye.\n");
          close(sockfd);
          break;
        }
        else
        {
          printf("Error: command not recoginzed.");
        }

      }
    }
    else if (isAdmin==1)
    {
      while(1)
      {
        clear_send_buff(sendBuf);
        printf("\nPlease enter a command:"); 
        fgets(input, 8, stdin);
        if (input[0]=='\n')
        {
          continue;
        }
        if (input[0]=='h')
        {
          // help menu
          print_options_admin();
        }
        else if (input[0]=='v')
        {
          // view all all accounts for a user
          sendBuf[0]='v';
          char username[64];

          printf("Enter a username: ");
          scanf("%s", username);

          memcpy(sendBuf+8, username, 64);
          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;

          struct all_accounts * user_accounts;
          user_accounts = (struct all_accounts *) recBuf;
          if ((*user_accounts).num_accounts==0)
          {
            printf("No accounts exist for the specified user.\n");
          }
          else
          {
            printf("NUMBER OF ACCOUNTS %d\n", (*user_accounts).num_accounts);
            print_accounts_info(user_accounts);
          }

        }
        else if (input[0]=='c')
        {
          // create a new account
          sendBuf[0]='c';

          char accountno[64];
          char username[64];
          char type[4];

          printf("Enter username of account owner: ");
          scanf("%s", username);
          printf("Enter an account no: ");
          scanf("%s", accountno);
          printf("Enter 0 for savings, 1 for checking: ");
          scanf("%s", &type);

          memcpy(sendBuf+8, username, 64);
          memcpy(sendBuf+72, accountno, 64);
          memcpy(sendBuf+136, type, 4);
          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;
          printf("Account successfully created. \n");

        }
        else if (input[0]=='u')
        {
          // create a new user
          sendBuf[0]='u';
          char username[32];
          char first[32];
          char last[32];
          char password1[32];
          char password2[32];

          printf("Enter new username: ");
          scanf("%s", username);
          printf("Enter a first and last name: ");
          scanf("%s %s", first, last );
          printf("Enter password: ");
          scanf("%s", password1);
          printf("Enter password: ");
          scanf("%s", password2);    
          if (strncmp(password1,password2,32)!=0)
          {
            printf("Error, passwords do not match.  Account not created.\n");
          }
          else
          {
            memcpy(sendBuf+8, username, 32);
            memcpy(sendBuf+40, password1, 32);
            memcpy(sendBuf+72, first, 32);
            memcpy(sendBuf+104, last, 32);
            if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;
            printf("Account successfully created. \n");
          }

        }
        else if (input[0]=='a')
        {
          // add funds to an account
          sendBuf[0]='a';
          char accountno[64];
          char funds[10];

          printf("Enter account no.: \n");
          scanf("%s", accountno);
          printf("Enter amount: \n");
          scanf("%s", funds);

          memcpy(sendBuf+8, accountno, 64);
          memcpy(sendBuf+72, funds, 10);

          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;
          printf("%s\n", (char *) recBuf);

        }
        else if (input[0]=='r')
        {
          // remove funds from an account
          sendBuf[0]='r';
          char accountno[64];
          char funds[10];

          printf("Enter account no.: \n");
          scanf("%s", accountno);
          printf("Enter amount: \n");
          scanf("%s", funds);

          memcpy(sendBuf+8, accountno, 64);
          memcpy(sendBuf+72, &funds, 10);

          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;
          printf("%s\n", (char *) recBuf);
        }
        else if (input[0]=='q')
        {
          // exits the applications safely, closing connection with server
          sendBuf[0]='q';
          if (do_request_reply(sockfd, sendBuf, recBuf, theKey, hashKey)==-1) return 0;
          else printf("Goodbye.\n");
          close(sockfd);
          break;
        }
        else
        {
          printf("Error: command not recoginzed.");
        }

      }
    }

  }


  return 0;
}
