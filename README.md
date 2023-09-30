
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
    nginx-http-auth-request:
        image: ghcr.io/klementng/nginx-http-auth-request:latest
        container_name: nginx-http-auth-request
        environment:
            - CONFIG_DIR=/config
            - SETTINGS_PATH=/config/settings.yml
            - USER_DB_PATH=/config/settings.yml
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
    <td>USERS_DB_PATH</td>
    <td>Path to settings file</td>
    <td>Any</td>
    <td>yaml: SETTINGS_PATH | sqlite3: ${CONFIG_DIR}/data.db</td>
  </tr>
</table>  

### Managing Users
```bash
sudo docker exec -it nginx-http-auth-request server.users add <username>
sudo docker exec -it nginx-http-auth-request server.users edit <username>
sudo docker exec -it nginx-http-auth-request server.users delete <username>
```
### Starting / killing server
```bash
sudo docker exec -it nginx-http-auth-request server.core start
sudo docker exec -it nginx-http-auth-request server.core kill
```

## Examples :

### Server
see [default.yml](examples/default.yml)

### Nginx
see [nginx.cong](examples/nginx.conf)
### Jellyfin
see [jellyfin.yml](examples/jellyfin.yml)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
