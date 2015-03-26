#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sqlite3.h>

//OpenSSL for Encryption
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "packet_structs.h"
#include "crypto_lib.h"

//variable for sql queries
//made global so they can be used by all functions easily
char query[1024];
int query_len=1024;
sqlite3_stmt *pStatement;
const char * pzTail;

int check_authentication(int connfd, sqlite3 *bank_db, struct user_pass enc_log_attempt, struct user_info * current_user)
{
  int authenticate=0;
  int isAdmin=0;

  // get the RSA keypair
  RSA *serverkey = RSA_new();
  FILE * publicKeyOut = fopen("pubkey.pem", "r");
  FILE * privateKeyOut =fopen("privkey.pem", "r");
  PEM_read_RSAPublicKey(publicKeyOut, &serverkey, NULL, NULL);
  PEM_read_RSAPrivateKey(privateKeyOut, &serverkey, NULL, NULL); 
  fclose(publicKeyOut);
  fclose(privateKeyOut);

  // decrypt data from client into another user_pass struct
  struct user_pass log_attempt;  

  if(RSA_private_decrypt(64, (unsigned char*)&enc_log_attempt.name, (unsigned char*)&log_attempt.name, serverkey, RSA_NO_PADDING)==-1)
  {
      char err[64];
      ERR_load_crypto_strings();
      ERR_error_string(ERR_get_error(), err);
      fprintf(stderr, "Error encrypting message: %s\n", err);
  }
  if(RSA_private_decrypt(64, (unsigned char*)&enc_log_attempt.pass, (unsigned char*)&log_attempt.pass, serverkey, RSA_NO_PADDING)==-1)
  {
      char err[64];
      ERR_load_crypto_strings();
      ERR_error_string(ERR_get_error(), err);
      fprintf(stderr, "Error encrypting message: %s\n", err);
  }

  sprintf(query, "select * from users where uname='%s'", log_attempt.name);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  while (sqlite3_step(pStatement)!=SQLITE_DONE)
  {
    char *password;
    password = (char *)sqlite3_column_text(pStatement,1);
    if (strcmp(password, log_attempt.pass)==0)
    {
      authenticate=1;
      strncpy((*current_user).uname, (char *) sqlite3_column_text(pStatement,0), 64);
      strncpy((*current_user).first, (char *) sqlite3_column_text(pStatement,2), 64);
      strncpy((*current_user).last, (char *) sqlite3_column_text(pStatement,3), 64);
      strncpy((*current_user).email, (char *) sqlite3_column_text(pStatement,4), 64);
      strncpy((*current_user).telephone, (char *) sqlite3_column_text(pStatement,5), 64);
      (*current_user).isAdmin = (int) sqlite3_column_int(pStatement,6);
    }
  }
  sqlite3_finalize(pStatement);

  if ((*current_user).isAdmin==1)
  {
    isAdmin=1;
  }
  else
  {
    isAdmin=0;
  }

  if(send(connfd, &authenticate, sizeof(int), 0)==-1)
  {
    printf("Error occured sending authentication info.");
    return 0;
  }
  if(send(connfd, &isAdmin, sizeof(int), 0)==-1)
  {
    printf("Error occured sending authentication info.");
    return 0;
  }

  return authenticate;
}

void get_user_accounts(sqlite3 *bank_db, struct user_info current_user, struct all_accounts * user_accounts)
{
  sprintf(query, "select * from accounts where uname='%s'", current_user.uname);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  int account_ct=0;
  while (sqlite3_step(pStatement)!=SQLITE_DONE)
  {
    struct accounts account;
    account.type=(int) sqlite3_column_int(pStatement,1);
    account.funds=(int) sqlite3_column_int(pStatement,2);
    strncpy(account.accountno, (char *) sqlite3_column_text(pStatement,3), 64);

    (*user_accounts).account_list[account_ct]=account;

    (*user_accounts).num_accounts=++account_ct;
  }
  sqlite3_finalize(pStatement);
}

void admin_get_user_accounts(sqlite3 *bank_db, char * user_name, struct all_accounts * user_accounts)
{
  sprintf(query, "select * from accounts where uname='%s'", user_name);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  int account_ct=0;
  (*user_accounts).num_accounts=0;
  while (sqlite3_step(pStatement)!=SQLITE_DONE)
  {
    struct accounts account;
    account.type=(int) sqlite3_column_int(pStatement,1);
    account.funds=(int) sqlite3_column_int(pStatement,2);
    strncpy(account.accountno, (char *) sqlite3_column_text(pStatement,3), 64);

    (*user_accounts).account_list[account_ct]=account;

    (*user_accounts).num_accounts=++account_ct;
  }
  sqlite3_finalize(pStatement);
} 

void admin_add_user(sqlite3 * bank_db, char * username, char * password, char * first, char * last)
{
  char default_string[12]="UNKNOWN";
  sprintf(query, "insert into users values ('%s', '%s', '%s', '%s', '%s', '%s', 0 )", username, password, first, last, default_string, default_string );
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);
}

void admin_create_new_account(sqlite3 *bank_db, char * username, char *accountno, char *type)
{
  int type_int=atoi(type);
  sprintf(query, "insert into accounts values ('%s', %d, 0, '%s')", username, type_int, accountno);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);
}

void get_user_transfers(sqlite3 * bank_db, struct user_info current_user, struct all_transfers * user_transfers)
{
  sprintf(query, "select * from transfer_log where uname='%s' order by time desc", current_user.uname);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  int trans_ct=0;
  while (sqlite3_step(pStatement)!=SQLITE_DONE && trans_ct<8)
  {
    struct transfer the_transfer;
    the_transfer.amount= (int) sqlite3_column_int(pStatement,3);
    strncpy(the_transfer.sender, (char *) sqlite3_column_text(pStatement,1),32);
    strncpy(the_transfer.receiver, (char *) sqlite3_column_text(pStatement,2) ,32);
    strncpy(the_transfer.date, (char *) sqlite3_column_text(pStatement,5), 32);

    (*user_transfers).transfer_list[trans_ct]=the_transfer;
    (*user_transfers).num_transfers=++trans_ct;
  }
  sqlite3_finalize(pStatement);
}

void attempt_transfer(sqlite3 * bank_db, struct transfer current_transfer, struct user_info current_user, char *result)
{
  struct accounts sender;
  struct accounts receiver;

  // gather info for transfer
  sprintf(query, "select * from accounts where account_no='%s' and uname='%s'", current_transfer.sender, current_user.uname);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  int check=0;
  int rc;
  if(rc=sqlite3_step(pStatement)!=SQLITE_DONE)
  {
    fflush(stdout);
    check++;
    sender.type = (int) sqlite3_column_int(pStatement,1);
    sender.funds = (int) sqlite3_column_int(pStatement,2);
    strncpy(sender.accountno, current_transfer.sender, 64);
  }
  sqlite3_finalize(pStatement);
  if(check==0)
  {
    sprintf(result, "Error, sender does not have rights to account with given number.\n");
    return;
  }

  sprintf(query, "select * from accounts where account_no='%s'", current_transfer.receiver);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  check=0;
  if(sqlite3_step(pStatement)!=SQLITE_DONE)
  {
    check++;
    receiver.type = (int) sqlite3_column_int(pStatement,1);
    receiver.funds = (int) sqlite3_column_int(pStatement,2);
    strncpy(receiver.accountno, current_transfer.receiver, 64);
  }
  sqlite3_finalize(pStatement);
  if(check==0)
  {
    sprintf(result, "Error, receiving account does not exits.\n");
    return;
  }

  // check for sufficient funds
  if (current_transfer.amount > sender.funds)
  {
    sprintf(result, "Error, insufficient funds.\n");
    return;
  }

  // update accounts, log transfer
  sender.funds-=current_transfer.amount;
  receiver.funds+=current_transfer.amount;
  
  sprintf(query, "update accounts set funds='%d' where account_no='%s'", sender.funds, sender.accountno);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);

  sprintf(query, "update accounts set funds='%d' where account_no='%s'", receiver.funds, receiver.accountno);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);

  sprintf(query, "insert into transfer_log (send_from, send_to, amount, uname) values('%s', '%s', %d, '%s')", sender.accountno, receiver.accountno, current_transfer.amount, current_user.uname);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);

  sprintf(result, "Transfer was a success.\n");
  return;

}

int admin_add_funds(sqlite3 *bank_db, char * account_no, char * funds)
{
  struct accounts currentAccount;
  int funds_int = atoi(funds);

  sprintf(query, "select * from accounts where account_no='%s'", account_no);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  int check=0;
  if(sqlite3_step(pStatement)!=SQLITE_DONE)
  {
    check++;
    currentAccount.funds = (int) sqlite3_column_int(pStatement,2);
  }
  sqlite3_finalize(pStatement);
  if(check==0)
  {
    return 0;
  }

  currentAccount.funds+= funds_int;

  sprintf(query, "update accounts set funds=%d where account_no='%s'", currentAccount.funds , account_no);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);

  return 1;

}

int admin_remove_funds(sqlite3 *bank_db, char * account_no, char * funds)
{
  struct accounts currentAccount;
  int funds_int = atoi(funds);

  sprintf(query, "select * from accounts where account_no='%s'", account_no);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  int check=0;
  if(sqlite3_step(pStatement)!=SQLITE_DONE)
  {
    check++;
    currentAccount.funds = (int) sqlite3_column_int(pStatement,2);
  }
  sqlite3_finalize(pStatement);
  if(check==0)
  {
    return 0;
  }

  currentAccount.funds-= funds_int;

  sprintf(query, "update accounts set funds=%d where account_no='%s'", currentAccount.funds , account_no);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);

  return 1;

}

void update_phone(sqlite3 *bank_db, struct user_info * currentUser, char * updateBuf)
{
  strncpy((*currentUser).telephone, updateBuf, 30);
  sprintf(query, "update users set phone='%s' where uname='%s'", (*currentUser).telephone, (*currentUser).uname);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);
}

void update_email(sqlite3 *bank_db, struct user_info * currentUser, char * updateBuf)
{
  strncpy((*currentUser).email, updateBuf, 30);
  sprintf(query, "update users set email='%s' where uname='%s'", (*currentUser).email, (*currentUser).uname);
  sqlite3_prepare(bank_db, query, query_len, &pStatement, &pzTail);
  sqlite3_step(pStatement);
  sqlite3_finalize(pStatement);
}

int encrypt_and_send(int connfd, unsigned char * sendBuf, unsigned char * theKey, unsigned char * hashKey)
{
  unsigned char encSendBuf[1024];  
  unsigned char iv[32];

  gen_iv(iv);

  memcpy(encSendBuf+960, iv, 32);

  unsigned char hashVal[32];

  aes_cbc_sec_enc(sendBuf, encSendBuf, 928, theKey, iv);

  compute_hash(encSendBuf, 928, hashVal, hashKey);
  memcpy(encSendBuf+928, hashVal, 32);

  if(send(connfd, encSendBuf, 1024, 0)==-1)
  {
    printf("An error occurred sending the request to the client.");
    close(connfd);  
    return -1;  
  }
  return 1;
}

int main(void)
{
  sqlite3 *bank_db;

  int rc;
  rc = sqlite3_open("accounts.db", &bank_db);
  if (rc)
  {
    fprintf(stderr, "Failed to open banking database: %s\n", sqlite3_errmsg(bank_db));
    sqlite3_close(bank_db);
    return 0;
  }

  int listenfd = 0,connfd = 0;
  struct sockaddr_in serv_addr;
  int numrv;  
  listenfd = socket(AF_INET, SOCK_STREAM, 0);

  printf("socket retrieve success\n");

  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;    
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
  serv_addr.sin_port = htons(5000);    
  bind(listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr));
  
  if(listen(listenfd, 10) == -1){
      printf("could not establish ability to listen\n");
      return 0;
  }

  //generate RSA keypair


  while(1)  
  {
    connfd = accept(listenfd, (struct sockaddr*)NULL ,NULL); // accept awaiting request
    fprintf(stdout, "Welcome to the bank.\n");

    while(1)
    {
      struct user_pass log_attempt;
      if(recv(connfd, &log_attempt, sizeof(struct user_pass), 0)==-1)
      {
        printf("An error occurred receiving the password.");
        close(connfd);    
        break;
      }
      else
      {
          // check authentication from database
          int authenticate = 0;
          struct user_info current_user;

          authenticate=check_authentication(connfd, bank_db, log_attempt, &current_user);

          if (authenticate==1)
          {
            // vars for keys
            unsigned char theKey[32];
            gen_secret_key(theKey);
            unsigned char hashKey[32];
            gen_secret_key(hashKey);

            // buffers for sending and receiving
            unsigned char sendBuf[1024];  
            unsigned char recBuf[256];
            unsigned char encRecBuf[256];

            // set up shared secret key using Diffie Hellman

            unsigned char publicKey[128];
            unsigned char P[256];

            gen_secret_key(P);

            unsigned long G = 2;

            DH* dh = DH_new();
            dh->p = BN_new();
            dh->g = BN_new();

            BN_set_word(dh->g, G);
            BN_bin2bn(P, 128, dh->p);
            if(DH_generate_key(dh))
            {
               BN_bn2bin(dh->pub_key, publicKey);
            }

            unsigned char P_send[128];
            unsigned char G_send[1];

            BN_bn2bin(dh->p, P_send);
            BN_bn2bin(dh->g, G_send);

            if(memcmp(P_send, P, 128)==0) printf("BLOCKS MATCH P.\n");
            else printf("Blocks do not match P.\n");

            if(memcmp(G_send, &G, 1)==0) printf("BLOCKS MATCH G.\n");
            else printf("Blocks do not match G.\n");

            memcpy(sendBuf, P_send, 128);
            memcpy(sendBuf+128, publicKey, 128);
            memcpy(sendBuf+256, G_send, 1);

            // send public DH info to client
            if(send(connfd, sendBuf, 1024, 0)==-1)
            {
              printf("An error occurred sending the request to the client.");
              close(connfd);    
              break;
            }

            // get the client's public key back
            if(recv(connfd, recBuf, 256, 0)==-1)
            {
                printf("Error occurred receiving the server response.");
                return -1;
            }  

            unsigned char clientPublicKey[128];
            memcpy(clientPublicKey, recBuf, 128);
            BIGNUM * pubKeyBN = BN_new();
            BN_bin2bn(clientPublicKey, 128, pubKeyBN);  

            unsigned char sharedKey[128];
            DH_compute_key(sharedKey, pubKeyBN, dh);

            memcpy(theKey, sharedKey, 32);

            memcpy(sendBuf, hashKey, 32);
        
            unsigned char iv[32];
            unsigned char encSendBuf[1024];
            gen_iv(iv);
            memcpy(encSendBuf+960, iv, 32);
            aes_cbc_sec_enc(sendBuf, encSendBuf, 928, theKey, iv);

            if(send(connfd, encSendBuf, 1024, 0)==-1)
            {
              printf("An error occurred sending the request to the client.");
              close(connfd);    
              break;
            }

            while(1)
            {
                if(recv(connfd, encRecBuf, 256, 0)==-1)
                {
                  printf("An error occurred receiving the request from the client.\n");
                  close(connfd);    
                  break;
                }
                else{

                  // decrypt message
                  unsigned char iv[32];
                  memcpy(iv, encRecBuf+200, 32);

                  unsigned char hashVal[32];
                  memcpy(hashVal, encRecBuf+160, 32);

                  if (verify_hash(encRecBuf, 160, hashVal, hashKey)==0)
                  {
                    printf("WARNING: HMAC not verified.  Data may be tampered with.\n");
                  }

                  aes_cbc_sec_dec(encRecBuf, recBuf, 160, theKey, iv);

                  char command = (char) recBuf[0];

                  if (current_user.isAdmin==0)
                  {
                    if (command=='a')
                    {
                      // get user account information
                      struct all_accounts user_accounts;
                      get_user_accounts(bank_db, current_user, &user_accounts);

                      memcpy(sendBuf, &user_accounts, sizeof(struct all_accounts));
                      if (encrypt_and_send(connfd, sendBuf, theKey,hashKey)==-1) return 0;
                    }
                    else if (command=='p')
                    {
                      // get user personal info
                      memcpy(sendBuf, &current_user, sizeof(struct user_info));
                      if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0;
                    }
                    else if (command=='t')
                    {
                      //attempt to do an account transfer
                      struct transfer current_transfer;
                      memcpy(&current_transfer, recBuf+1, sizeof(struct transfer));

                      char result[128];
                      attempt_transfer(bank_db, current_transfer, current_user, result);

                      memcpy(sendBuf, result, 128);
                      if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0;
                    }
                    else if (command=='i')
                    {
                      char choice = recBuf[1];
                      char updateBuf[30];
                      memcpy(updateBuf, recBuf+2, 30);
                      if (choice=='e')
                      {
                        update_email(bank_db, &current_user, updateBuf);
                        memcpy(sendBuf, "success", 20);
                        if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0;
                      }
                      else if (choice=='t')
                      {
                        update_phone(bank_db, &current_user, updateBuf);
                        memcpy(sendBuf, "success", 20);
                        if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0;
                      }
                    }
                    else if (command=='l')
                    {
                      struct all_transfers user_transfers;
                      get_user_transfers(bank_db, current_user, &user_transfers);

                      memcpy(sendBuf, &user_transfers, sizeof(struct all_transfers));
                      if (encrypt_and_send(connfd, sendBuf, theKey,hashKey)==-1) return 0;
                    }
                    else if (command=='q')
                    {
                      memcpy(sendBuf, "success", 20);
                      if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0;
                      close(connfd);
                      break;
                    }
                  }
                  else if (current_user.isAdmin==1)
                  {
                    int result=0;
                    if (command=='v')
                    {
                      struct all_accounts user_accounts;
                      admin_get_user_accounts(bank_db, (char *)recBuf+8, &user_accounts);

                      memcpy(sendBuf, &user_accounts, sizeof(struct all_accounts));
                      if (encrypt_and_send(connfd, sendBuf, theKey,hashKey)==-1) return 0;
                    }
                    else if (command=='c')
                    {
                      admin_create_new_account(bank_db, (char *)recBuf+8, (char *)recBuf+72, (char *)recBuf+136);
                      memcpy(sendBuf, "success", 20);
                      if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0; 
                    }
                    else if (command=='u')
                    {
                      admin_add_user(bank_db, (char *) recBuf+8, (char *) recBuf+40, (char *) recBuf+72, (char *) recBuf+104);
                      
                      memcpy(sendBuf, "success", 20);
                      if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0; 
                    }   
                    else if (command=='a')
                    {
                      result = admin_add_funds(bank_db, (char *) recBuf+8, (char *)recBuf+72);
                      if (result==1)
                      {
                        memcpy(sendBuf, "Funds added.", 32);
                      }
                      else
                      {
                        memcpy(sendBuf, "Account doesn't exist.", 32);
                      }
                      if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0;  
                    }    
                    else if (command=='r')
                    {
                      result = admin_remove_funds(bank_db, (char *) recBuf+8, (char *)recBuf+72);
                      if (result==1)
                      {
                        memcpy(sendBuf, "Funds removed.", 32);
                      }
                      else
                      {
                        memcpy(sendBuf, "Account doesn't exist.", 32);
                      }
                      if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0;  
                    }                  
                    else if (command=='q')
                    {
                      memcpy(sendBuf, "success", 20);
                      if (encrypt_and_send(connfd, sendBuf, theKey, hashKey)==-1) return 0;
                      close(connfd);
                      break;
                    }
                  }

                }
            }
          }
          authenticate=0;
      }
    } 
    sleep(1);
  }

  close(connfd);
  close(listenfd);    
  sqlite3_close(bank_db);
 
  return 0;
}