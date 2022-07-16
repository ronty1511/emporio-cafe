# Emporio Cafe


This is a simple food ordering app that uses JWT for authentication, postgres DB for customer and order data storage and redis cache for rate limiting.
The way this works is:
1. User signs up/logs in.
2. A token is generated that is valid for 15 mins and is present in orders page URL which is where the user is redirected to. Honestly I think having the token in the URL is not a good idea but this is just for JWT demonstration purposes. As an alternative, sessions can be used. This token is passed to orders page and view orders page, all of which run an additional layer of authentication with the token.
3. In the orders page, user can specify item name and the quantity of the item he wishes to have and hit submit. There are two tables, one for keeping customer information and the other for keeping order details. The customer table stores customer id and hashed password (password is encrypted before it is put in the table). The orders table stores item name, quantity and customer id of the customer who ordered it.
4. After placing orders, user can view past orders as well.
5. To achieve rate limiting, a custom rate limiter has been implemented (following token bucket approach) using redis cache which maps the IP address of client to the last time they invoked any API and remaining number of hits for that second (3 API hits per second). It must be noted that this is only for single server and can get quite complicated for distributed applications which requires a discussion on its own.
6. All these components (the app, database, cache) are put inside a docker-compose.yml file.

To be able to use this:

1. You must have docker installed. 
2. Change to emporio-cafe directory and run 'docker-compose up --build'. This will build three containers for you. The DB and cache ports have been exposed just in case you want to bash inside them and run commands.
3. Open localhost:5000 and start exploring.

Cheers!
