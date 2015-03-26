create table users(
	uname varchar(30),
	password varchar(30),
	first varchar(30),
	last varchar (30),
	email varchar (30),
	phone varchar (30),
	isAdmin smallint
);

create table accounts(
	uname varchar(30),
	type int,
	funds int,
	account_no varchar(30)
);

create table transfer_log(
	TID INTEGER PRIMARY KEY,
	send_from varchar(30),
	send_to varchar(30),
	amount int,
	uname varchar(30),
	time datetime DEFAULT CURRENT_TIMESTAMP
);

insert into users values ('jquinn11', 'test', 'John', 'Quinn', 'jquinn11@nd.edu', '867-5309', 0 );
insert into users values ('admin', 'admin', 'Joe', 'Smith', 'jsmith12@gmail.com', '555-5555', 1 );

insert into accounts values ('jquinn11', 0, 10000, '45654543');
insert into accounts values ('jquinn11', 1, 600, '43221123');
