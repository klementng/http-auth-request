
<a name="readme-top"></a>


# Nginx HTTP Authentication

<!-- ABOUT THE PROJECT -->
## About The Project

This project provide a simple way to manage users and provide basic access control using HTTP basic authentication and nginx auth_request. 

Notes: this project current only support HTTP basic authentication which must be used with SSL.

## Installation

### Docker Compose
```yaml
services:
    http-auth-request:
        image: ghcr.io/klementng/http-auth-request:latest
        container_name: http-auth-request
        environment:
            - CONFIG_DIR=/config
            - SETTINGS_PATH=/config/settings.yml
            - USER_DB_PATH=/config/settings.yml
            - CACHE_TTL=60
            - LOG_LEVEL=INFO
            - FLASK_SESSION_COOKIE_DOMAIN=.example.com
        volumes:
            - /path/to/data:/config
        ports:
            - 9999:9999
        restart: unless-stopped
```
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage:

### Server Setup
Docker environmental variables:
<table>
  <tr>
    <th>Name</th>
    <th>Description</th>
    <th>Allowed values</th>
    <th>Default values</th>
  </tr>
  <tr>
    <td>CONFIG_DIR</td>
    <td>Working directory for storing configuration & data </td>
    <td>Any</td>
    <td>/config</td>
  </tr>
  <tr>
    <td>CACHE_TTL</td>
    <td>Header Cache TTL (seconds) </td>
    <td>float</td>
    <td>60</td>
  </tr>
  <tr>
    <td>SETTINGS_PATH</td>
    <td>Path to settings file</td>
    <td>Any</td>
    <td>${CONFIG_DIR}/settings.yml</td>
  </tr>
  <tr>
    <td>LOG_LEVEL</td>
    <td>Set Logging</td>
    <td>INFO, DEBUG, WARNING</td>
    <td>INFO</td>
  </tr>

  <tr>
    <td>FLASK_SESSION_COOKIE_DOMAIN</td>
    <td>Path to settings file</td>
    <td>Any</td>
    <td>-</td>
  </tr>

  <tr>
    <td>FLASK_*</td>
    <td>Flask app config</td>
    <td>Any</td>
    <td>-</td>
  </tr>

</table>  

### Managing Users
```bash
sudo docker exec -it http-auth-request server.users add <username>
sudo docker exec -it http-auth-request server.users edit <username>
sudo docker exec -it http-auth-request server.users delete <username>
```

## Examples :

### Server
see [default.yml](examples/default.yml)

### Nginx
see [auth-request.conf](examples/auth-request.conf)
and [nginx.conf](examples/nginx.conf)

### Jellyfin
see [jellyfin.yml](examples/jellyfin.yml)

<p align="right">(<a href="#readme-top">back to top</a>)</p>