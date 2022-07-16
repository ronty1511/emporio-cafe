create table ORDERS (
	order_id		serial primary key,
	customer_id 	VARCHAR(30) not null,
	item 			varchar(50) not null,
	qty 			varchar(5) not null
);

create table CUSTOMERS (
	customer_id		VARCHAR(25) not null,
	hashed_passwd	VARCHAR(150) not null
);