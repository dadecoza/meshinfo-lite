# MeshInfo-Lite Docker Setup Guide

This guide covers setting up MeshInfo-Lite with Docker Compose, including proper database privileges.

## Prerequisites

- Docker and Docker Compose installed
- Git (to clone the repository)

## Quick Setup

### 1. Clone and Configure

```bash
# Clone the repository
git clone <repository-url>
cd meshinfo-lite

# Copy the sample configuration
cp docker-compose.yml.sample docker-compose.yml
cp config.ini.sample config.ini
```

### 2. Configure Database Settings

Edit your `config.ini` file:

```ini
[database]
host = mariadb
username = meshdata
password = passw0rd
database = meshdata
root_password = passw0rd
```

**Note**: In Docker Compose, the database host is the service name (`mariadb`), not `localhost`.

### 3. Start Docker Services

```bash
# Start the services
docker-compose up -d

# Check that services are running
docker-compose ps
```

### 4. Set Up Database Privileges

**Important**: The Docker Compose setup automatically creates the database, user, and tables, but **does not grant all the privileges needed for optimal performance**.

**What's Created Automatically:**
- ✅ Database (`meshdata`)
- ✅ User (`meshdata`) 
- ✅ All application tables
- ✅ Basic database operations (SELECT, INSERT, UPDATE, DELETE)

**What's Missing:**
- ❌ RELOAD privilege (needed for query cache operations)
- ❌ PROCESS privilege (needed for monitoring)

You have two options to complete the setup:

#### Option A: Python Setup Script (Recommended)

```bash
# Run the Python setup script
python setup_docker.py
```

#### Option B: Shell Script (Alternative)

```bash
# Run the shell script inside the container
docker-compose exec meshinfo ./docker_setup.sh
```

Both scripts will:
- ✅ Wait for the database to become available
- ✅ Grant RELOAD privilege for query cache operations
- ✅ Grant PROCESS privilege for monitoring
- ✅ Test the connection and privileges
- ✅ Provide detailed feedback

### 5. Verify Setup

Check that everything is working:

```bash
# Check application logs
docker-compose logs meshinfo

# Test the application
curl http://localhost:8001/
```

## What the Setup Script Does

The `setup_docker.py` script performs these operations:

1. **Waits for Database**: Ensures MariaDB is fully started and ready
2. **Connects as Root**: Uses root credentials to grant privileges
3. **Grants RELOAD**: Allows query cache clearing operations
4. **Grants PROCESS**: Enables monitoring and debugging
5. **Tests Everything**: Verifies the setup worked correctly

## Docker Compose Configuration

The typical `docker-compose.yml` includes:

```yaml
services:
  mariadb:
    image: mariadb
    environment:
      MYSQL_ROOT_PASSWORD: passw0rd
      MYSQL_DATABASE: meshdata
      MYSQL_USER: meshdata
      MYSQL_PASSWORD: passw0rd
    volumes:
      - ./mysql_data:/var/lib/mysql
      - ./custom.cnf:/etc/mysql/conf.d/custom.cnf

  meshinfo:
    build: .
    depends_on:
      - mariadb
    volumes:
      - ./config.ini:/app/config.ini
    ports:
      - 8001:8000
```

## Manual Setup (Alternative)

If you prefer to set up privileges manually:

### 1. Connect to the MariaDB Container

```bash
# Connect to the MariaDB container
docker-compose exec mariadb mysql -u root -p
# Password: passw0rd
```

### 2. Grant Privileges

```sql
-- Grant RELOAD privilege for query cache operations
GRANT RELOAD ON *.* TO 'meshdata'@'%';

-- Grant PROCESS privilege for monitoring
GRANT PROCESS ON *.* TO 'meshdata'@'%';

-- Apply changes
FLUSH PRIVILEGES;
```

### 3. Test Privileges

```sql
-- Test RELOAD privilege
FLUSH QUERY CACHE;

-- Test PROCESS privilege
SHOW PROCESSLIST;
```

## Troubleshooting

### Common Issues

1. **"Database not available"**
   ```bash
   # Check if services are running
   docker-compose ps
   
   # Check MariaDB logs
   docker-compose logs mariadb
   
   # Restart services
   docker-compose restart
   ```

2. **"Access denied for user"**
   - Verify the database credentials in `config.ini`
   - Check that the MariaDB container is fully started
   - Run the setup script again

3. **"Access denied; you need RELOAD privilege"**
   - Run `python setup_docker.py` to grant privileges
   - Or manually grant privileges as shown above

4. **"Cannot connect to database"**
   - Check that the host is set to `mariadb` (not `localhost`)
   - Verify the Docker network is working
   - Check container logs: `docker-compose logs`

### Debug Commands

```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs meshinfo
docker-compose logs mariadb

# Connect to database container
docker-compose exec mariadb mysql -u meshdata -p meshdata

# Check application health
curl http://localhost:8001/api/debug/database-cache
```

## Production Considerations

### Security

- Change default passwords in production
- Use Docker secrets for sensitive data
- Restrict network access to the database container
- Consider using a managed database service

### Performance

- Adjust MariaDB configuration in `custom.cnf`
- Monitor memory usage and adjust container limits
- Use persistent volumes for data storage
- Consider database backups

### Monitoring

- Set up log aggregation
- Monitor container resource usage
- Use health checks for automated monitoring
- Set up alerts for critical issues

## Next Steps

After setup is complete:

1. **Configure MQTT**: Set up your MQTT broker connection
2. **Import Data**: Import existing node data if available
3. **Customize**: Add your logo and customize the interface
4. **Monitor**: Set up monitoring and alerting
5. **Backup**: Configure regular database backups

## Getting Help

- Check the application logs: `docker-compose logs meshinfo`
- Use debug endpoints: `http://localhost:8001/api/debug/`
- Review the main documentation in `CACHING.md`
- Check the general setup guide in `SETUP.md` 