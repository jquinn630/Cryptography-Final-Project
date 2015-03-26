struct user_pass
{
	char name[64];
	char pass[64];
};

struct transfer
{
	char sender[32];
	char receiver[32];
	int amount;
	char date[32];
};

struct all_transfers
{
	int num_transfers;
	struct transfer transfer_list[8];
};

struct user_info
{
	char uname[64];
	char first[64];
	char last[64];
	char email[64];
	char telephone[64];
	int isAdmin;
};

struct accounts
{
	int type;
	int funds;
	char accountno[64];
};

struct all_accounts
{
	int num_accounts;
	struct accounts account_list[8];
};