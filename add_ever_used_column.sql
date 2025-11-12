-- Add ever_used column to used_domain table
-- Run this SQL script in your PostgreSQL database

-- Check if column exists first
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'used_domain' AND column_name = 'ever_used'
    ) THEN
        -- Add the column
        ALTER TABLE used_domain ADD COLUMN ever_used BOOLEAN DEFAULT FALSE;
        
        -- Update existing records: if user_count > 0, set ever_used = TRUE
        UPDATE used_domain SET ever_used = TRUE WHERE user_count > 0;
        
        -- Show results
        RAISE NOTICE 'Column ever_used added successfully!';
        RAISE NOTICE 'Updated % records with ever_used=TRUE', (SELECT COUNT(*) FROM used_domain WHERE ever_used = TRUE);
    ELSE
        RAISE NOTICE 'Column ever_used already exists!';
    END IF;
END $$;

-- Show current status
SELECT 
    COUNT(*) as total_domains,
    COUNT(CASE WHEN ever_used = TRUE THEN 1 END) as ever_used_domains,
    COUNT(CASE WHEN ever_used = FALSE THEN 1 END) as available_domains,
    COUNT(CASE WHEN user_count > 0 THEN 1 END) as in_use_domains
FROM used_domain;
