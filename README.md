# BasicPHPcrud
Basic PHP RESTful MySQL backend with JWT based authorization/authentication

## Authorization header
Depending on the web server settings changes to the configuration might be necessary (see file `.htaccess`) for the server to pass the authorization header to the PHP interpreter in the global variable `$_SERVER`. Also, depending on the server settings the header will be passed in the field `HTTP_AUTHORIZATION` or `REDIRECT_HTTP_AUTHORIZATION`, which can be accounted for in the configuration variable `$auth_header_field`.

## Conventions
All database tables must have an autoincrement column named **id** for the primary key.

## User handling
The authentication scheme expects a database table for user (with columns for username, password hash, mail address, and reset code), one for userroles (column for role name), and a corresponding join table.
The foreign key columns' names must consist of the referenced table's name suffixed with **_id**. The join table's name must consist of the user table's and the role table's name with a joining **_**.
All other table/column names are arbitrary.

With the config variable `$user_meta['allowed_fields']` can the request to the user table be restricted to the defined columns.

A path filter can be defined with the config variable `$auth_filter`. An array of user roles with the path name as key will restrict the access to users with at least one listed role.

## Login
For login a JSON body with the fields `user` and `password` must be POSTed to `/api/login`. The JSON response will contain the `token` in the field `jwt`, which has to be passed as Bearer token in the Auth Header of all requests to `/api/v1/*`, expiration date in `expires`, and the roles of the user. The validity period of the token can be set in the variable `$validity` in `login.php`.

## Dependencies
The authorization with JWT depends on Firebase/JWT. You have to install it by Composer or manually.
