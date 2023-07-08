API Endpoints:

Authentication:

Register User

URL: /auth/register
Method: POST
Description: Register a new user.
Request Body:
username (string): User's username.
password (string): User's password.
User Login

URL: /auth/login
Method: POST
Description: User login.
Request Body:
username (string): User's username.
password (string): User's password.
Ping

URL: /app/ping
Method: GET
Description: Ping endpoint for testing server connectivity.
Authentication: JWT required.
Get Polls

URL: /app/polls
Method: GET
Description: Retrieve all polls.
Authentication: JWT required.
Create/Update Poll

URL: /app/polls
Method: POST
Description: Create or update a poll.
Authentication: JWT required.
Get Poll

URL: /app/polls/{url}
Method: GET
Description: Retrieve a specific poll by URL.
Authentication: JWT required.
Update Poll

URL: /app/polls/{url}
Method: PUT
Description: Update a specific poll by URL.
Authentication: JWT required.
Delete Poll

URL: /app/polls/{url}
Method: DELETE
Description: Delete a specific poll by URL.
Authentication: JWT required.
Vote on Poll

URL: /app/polls/vote/{url}
Method: POST
Description: Vote on a specific poll by URL.
Authentication: JWT required.
Create Option

URL: /app/polls/{poll_url}/options
Method: POST
Description: Create an option for a specific poll.
Authentication: JWT required.
Get Option

URL: /app/polls/{poll_url}/options/{option_id}
Method: GET
Description: Retrieve a specific option for a poll.
Authentication: JWT required.
Update Option

URL: /app/polls/{poll_url}/options/{option_id}
Method: PUT
Description: Update a specific option for a poll.
Authentication: JWT required.
Delete Option

URL: /app/polls/{poll_url}/options/{option_id}
Method: DELETE
Description: Delete a specific option for a poll.
Authentication: JWT required.
Please note that all endpoints except for the authentication endpoints (/auth/register and /auth/login) require JWT authentication.