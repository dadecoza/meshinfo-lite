#!/bin/bash
# Docker Setup Script for MeshInfo-Lite
# This script can be run inside the Docker container to set up database privileges

set -e

echo "=== MeshInfo-Lite Docker Database Setup ==="

# Wait for database to be ready
echo "Waiting for database to become available..."
for i in {1..30}; do
    if mysql -h mariadb -u root -ppassw0rd -e "SELECT 1" >/dev/null 2>&1; then
        echo "✓ Database is available"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "✗ Database failed to become available"
        exit 1
    fi
    echo "Database not ready yet (attempt $i/30)..."
    sleep 2
done

# Grant privileges
echo "Setting up database privileges..."

mysql -h mariadb -u root -ppassw0rd << EOF
-- Grant RELOAD privilege for query cache operations
GRANT RELOAD ON *.* TO 'meshdata'@'%';

-- Grant PROCESS privilege for monitoring
GRANT PROCESS ON *.* TO 'meshdata'@'%';

-- Apply changes
FLUSH PRIVILEGES;
EOF

echo "✓ Granted RELOAD privilege for query cache operations"
echo "✓ Granted PROCESS privilege for monitoring"
echo "✓ Privileges flushed"

# Test privileges
echo "Testing privileges..."
if mysql -h mariadb -u meshdata -ppassw0rd meshdata -e "FLUSH QUERY CACHE" >/dev/null 2>&1; then
    echo "✓ RELOAD privilege verified"
else
    echo "⚠ RELOAD privilege test failed"
fi

if mysql -h mariadb -u meshdata -ppassw0rd meshdata -e "SHOW PROCESSLIST" >/dev/null 2>&1; then
    echo "✓ PROCESS privilege verified"
else
    echo "⚠ PROCESS privilege test failed"
fi

echo "=== Docker Setup Complete ==="
echo "The MeshInfo-Lite application should now have full functionality" 