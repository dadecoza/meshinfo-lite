#!/bin/bash

# Cleanup corrupted timestamp data in message_reception table
# This script removes records with future timestamps or very old timestamps that are likely corrupted

set -e

echo "=== MeshInfo Database Timestamp Cleanup ==="
echo "This script will clean up corrupted timestamp data in the message_reception table"
echo ""

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "Error: docker-compose.yml not found. Please run this script from the project root directory."
    exit 1
fi

# Check if containers are running
if ! docker compose ps | grep -q "mariadb.*Up"; then
    echo "Error: MariaDB container is not running. Please start the services first:"
    echo "  docker compose up -d"
    exit 1
fi

echo "Checking for corrupted timestamp data..."

# Count bad records before cleanup
BAD_RECORDS=$(docker compose exec -T mariadb mariadb -u root -ppassw0rd meshdata -e "
SELECT COUNT(*) FROM message_reception WHERE rx_time > UNIX_TIMESTAMP() + 86400;
" 2>/dev/null | tail -n 1)

OLD_RECORDS=$(docker compose exec -T mariadb mariadb -u root -ppassw0rd meshdata -e "
SELECT COUNT(*) FROM message_reception WHERE rx_time < UNIX_TIMESTAMP() - (5 * 365 * 24 * 3600);
" 2>/dev/null | tail -n 1)

echo "Found $BAD_RECORDS records with future timestamps (>24 hours ahead)"
echo "Found $OLD_RECORDS records with very old timestamps (>5 years ago)"

if [ "$BAD_RECORDS" -eq 0 ] && [ "$OLD_RECORDS" -eq 0 ]; then
    echo "No corrupted timestamp data found. Database is clean!"
    exit 0
fi

echo ""
echo "Cleaning up corrupted timestamp data..."

# Clean up future timestamps
if [ "$BAD_RECORDS" -gt 0 ]; then
    echo "Removing $BAD_RECORDS records with future timestamps..."
    docker compose exec -T mariadb mariadb -u root -ppassw0rd meshdata -e "
    DELETE FROM message_reception WHERE rx_time > UNIX_TIMESTAMP() + 86400;
    "
fi

# Clean up very old timestamps
if [ "$OLD_RECORDS" -gt 0 ]; then
    echo "Removing $OLD_RECORDS records with very old timestamps..."
    docker compose exec -T mariadb mariadb -u root -ppassw0rd meshdata -e "
    DELETE FROM message_reception WHERE rx_time < UNIX_TIMESTAMP() - (5 * 365 * 24 * 3600);
    "
fi

# Verify cleanup
REMAINING_RECORDS=$(docker compose exec -T mariadb mariadb -u root -ppassw0rd meshdata -e "
SELECT COUNT(*) FROM message_reception;
" 2>/dev/null | tail -n 1)

echo ""
echo "=== Cleanup Complete ==="
echo "Remaining records in message_reception table: $REMAINING_RECORDS"
echo ""
echo "The corrupted timestamp data has been removed."
echo "This should fix the 'negative minutes ago' display issues in the map interface." 