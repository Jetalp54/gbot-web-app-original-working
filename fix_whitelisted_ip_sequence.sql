-- Fix PostgreSQL sequence sync issue for whitelisted_ip table
-- Run this script on your production PostgreSQL database

-- Check current state
SELECT 'Current max ID:' as status, MAX(id) as value FROM whitelisted_ip;
SELECT 'Current sequence value:' as status, last_value as value FROM whitelisted_ip_id_seq;

-- Fix the sequence to be one higher than the max ID
SELECT setval('whitelisted_ip_id_seq', (SELECT COALESCE(MAX(id), 0) + 1 FROM whitelisted_ip));

-- Verify the fix
SELECT 'New sequence value:' as status, last_value as value FROM whitelisted_ip_id_seq;

-- Clean up any duplicate IPs (keep only the first occurrence)
DELETE FROM whitelisted_ip 
WHERE id NOT IN (
    SELECT MIN(id) 
    FROM whitelisted_ip 
    GROUP BY ip_address
);

-- Show final state
SELECT 'Final max ID:' as status, MAX(id) as value FROM whitelisted_ip;
SELECT 'Final sequence value:' as status, last_value as value FROM whitelisted_ip_id_seq;

-- Show all whitelisted IPs
SELECT 'Whitelisted IPs:' as status, COUNT(*) as count FROM whitelisted_ip;
SELECT id, ip_address, created_at FROM whitelisted_ip ORDER BY id;
