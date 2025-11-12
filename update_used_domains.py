#!/usr/bin/env python3
"""
Script to update all used subdomains to be properly marked as used in the database.
This ensures that domains that have been used before are marked as ever_used=True.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from database import UsedDomain, GoogleAccount
from sqlalchemy import text, func
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_used_domains():
    """Update all domains that should be marked as used"""
    
    with app.app_context():
        try:
            logger.info("🔄 Starting comprehensive domain usage update...")
            
            # Get all Google accounts to find domains that are actually being used
            accounts = GoogleAccount.query.all()
            logger.info(f"📊 Found {len(accounts)} Google accounts")
            
            # Extract domains from account names
            used_domains = set()
            domain_user_counts = {}
            
            for account in accounts:
                account_name = account.account_name
                if '@' in account_name:
                    domain = account_name.split('@')[1]
                    used_domains.add(domain)
                    domain_user_counts[domain] = domain_user_counts.get(domain, 0) + 1
            
            logger.info(f"📋 Found {len(used_domains)} unique domains in use: {sorted(used_domains)}")
            
            # Get all existing domain records
            existing_domains = {d.domain_name: d for d in UsedDomain.query.all()}
            logger.info(f"📋 Found {len(existing_domains)} existing domain records")
            
            updated_count = 0
            created_count = 0
            
            # Update or create records for domains that are actually being used
            for domain in used_domains:
                user_count = domain_user_counts.get(domain, 0)
                
                if domain in existing_domains:
                    # Update existing record
                    domain_record = existing_domains[domain]
                    old_ever_used = domain_record.ever_used
                    old_user_count = domain_record.user_count
                    
                    domain_record.user_count = user_count
                    domain_record.ever_used = True
                    domain_record.is_verified = True
                    domain_record.updated_at = db.func.current_timestamp()
                    
                    updated_count += 1
                    logger.info(f"✅ Updated domain {domain}: users={user_count}, ever_used={old_ever_used}->True")
                else:
                    # Create new record
                    new_domain = UsedDomain(
                        domain_name=domain,
                        user_count=user_count,
                        is_verified=True,
                        ever_used=True
                    )
                    db.session.add(new_domain)
                    created_count += 1
                    logger.info(f"✅ Created domain {domain}: users={user_count}, ever_used=True")
            
            # Also mark domains that have ever_used=True but user_count=0 as used
            for domain_name, domain_record in existing_domains.items():
                if domain_record.ever_used and domain_record.user_count == 0:
                    # This is a domain that was used before but has no current users
                    # Keep it marked as used
                    logger.info(f"📌 Domain {domain_name} already marked as used (no current users)")
            
            # Commit all changes
            db.session.commit()
            
            logger.info(f"🎉 Domain update completed!")
            logger.info(f"   📊 Updated: {updated_count} domains")
            logger.info(f"   📊 Created: {created_count} domains")
            logger.info(f"   📊 Total domains in database: {UsedDomain.query.count()}")
            
            # Show final status
            used_domains_count = UsedDomain.query.filter(UsedDomain.ever_used == True).count()
            available_domains_count = UsedDomain.query.filter(
                UsedDomain.ever_used == False,
                UsedDomain.user_count == 0
            ).count()
            
            logger.info(f"📈 Final status:")
            logger.info(f"   🔴 Used domains: {used_domains_count}")
            logger.info(f"   🟢 Available domains: {available_domains_count}")
            
            # Show some examples
            used_domains_list = UsedDomain.query.filter(UsedDomain.ever_used == True).limit(10).all()
            logger.info(f"📋 Sample used domains: {[d.domain_name for d in used_domains_list]}")
            
        except Exception as e:
            logger.error(f"❌ Error updating domains: {e}")
            db.session.rollback()
            raise

def mark_all_domains_as_used():
    """Mark ALL domains in the database as used (use with caution)"""
    
    with app.app_context():
        try:
            logger.info("⚠️  WARNING: Marking ALL domains as used...")
            
            # Get all domain records
            all_domains = UsedDomain.query.all()
            logger.info(f"📊 Found {len(all_domains)} domains to mark as used")
            
            updated_count = 0
            for domain in all_domains:
                if not domain.ever_used:
                    domain.ever_used = True
                    domain.updated_at = db.func.current_timestamp()
                    updated_count += 1
                    logger.info(f"✅ Marked {domain.domain_name} as used")
            
            db.session.commit()
            logger.info(f"🎉 Marked {updated_count} domains as used!")
            
        except Exception as e:
            logger.error(f"❌ Error marking domains as used: {e}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Update domain usage status')
    parser.add_argument('--mark-all', action='store_true', 
                       help='Mark ALL domains as used (use with caution)')
    
    args = parser.parse_args()
    
    if args.mark_all:
        mark_all_domains_as_used()
    else:
        update_used_domains()
