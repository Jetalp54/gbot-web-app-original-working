#!/usr/bin/env python3
"""
GBot Web Application - Intelligent Installation System
This script handles installation, reinstallation, and configuration validation
"""

import os
import sys
import subprocess
import json
import hashlib
import shutil
import platform
import sqlite3
try:
    import psutil
except ImportError:
    psutil = None
from pathlib import Path
import configparser
import requests
import time

class GBotInstaller:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.install_log = self.project_root / "install.log"
        self.config_file = self.project_root / "install_config.json"
        self.checksums_file = self.project_root / "checksums.json"
        self.installation_status = {}
        self.system_info = self._get_system_info()
        
    def _get_system_info(self):
        """Get comprehensive system information"""
        return {
            'os': platform.system(),
            'os_version': platform.version(),
            'architecture': platform.architecture()[0],
            'python_version': sys.version,
            'python_executable': sys.executable,
            'current_user': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
            'home_directory': str(Path.home()),
            'project_directory': str(self.project_root)
        }
    
    def log(self, message, level="INFO"):
        """Log installation messages"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        
        with open(self.install_log, 'a', encoding='utf-8') as f:
            f.write(log_entry + "\n")
    
    def check_prerequisites(self):
        """Check if all prerequisites are met"""
        self.log("Checking system prerequisites...")
        
        prerequisites = {
            'python_version': self._check_python_version(),
            'pip_available': self._check_pip_available(),
            'git_available': self._check_git_available(),
            'disk_space': self._check_disk_space(),
            'memory': self._check_memory(),
            'internet_connection': self._check_internet_connection()
        }
        
        all_met = all(prerequisites.values())
        
        if all_met:
            self.log("All prerequisites met successfully", "SUCCESS")
        else:
            self.log("Some prerequisites are not met", "WARNING")
            for prereq, status in prerequisites.items():
                if not status:
                    self.log(f"  - {prereq}: FAILED", "ERROR")
        
        return all_met
    
    def _check_python_version(self):
        """Check if Python version is compatible"""
        version = sys.version_info
        if version.major == 3 and version.minor >= 8:
            self.log(f"Python {version.major}.{version.minor}.{version.micro} is compatible")
            return True
        else:
            self.log(f"Python {version.major}.{version.minor}.{version.micro} is not compatible (requires 3.8+)", "ERROR")
            return False
    
    def _check_pip_available(self):
        """Check if pip is available"""
        try:
            subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                         capture_output=True, check=True)
            self.log("pip is available")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log("pip is not available", "ERROR")
            return False
    
    def _check_git_available(self):
        """Check if git is available"""
        try:
            subprocess.run(['git', '--version'], capture_output=True, check=True)
            self.log("git is available")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log("git is not available", "WARNING")
            return False
    
    def _check_disk_space(self):
        """Check available disk space"""
        try:
            stat = shutil.disk_usage(self.project_root)
            free_gb = stat.free / (1024**3)
            if free_gb >= 1.0:  # At least 1GB free
                self.log(f"Disk space: {free_gb:.2f}GB available")
                return True
            else:
                self.log(f"Insufficient disk space: {free_gb:.2f}GB available (need 1GB+)", "ERROR")
                return False
        except Exception as e:
            self.log(f"Could not check disk space: {e}", "WARNING")
            return True  # Assume OK if we can't check
    
    def _check_memory(self):
        """Check available memory"""
        if psutil is None:
            self.log("psutil not available, skipping memory check", "WARNING")
            return True  # Assume OK if we can't check
        
        try:
            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024**3)
            if available_gb >= 0.5:  # At least 512MB available
                self.log(f"Memory: {available_gb:.2f}GB available")
                return True
            else:
                self.log(f"Low memory: {available_gb:.2f}GB available (need 512MB+)", "WARNING")
                return False
        except Exception as e:
            self.log(f"Could not check memory: {e}", "WARNING")
            return True  # Assume OK if we can't check
    
    def _check_internet_connection(self):
        """Check internet connectivity"""
        try:
            response = requests.get('https://pypi.org/simple/', timeout=5)
            if response.status_code == 200:
                self.log("Internet connection available")
                return True
            else:
                self.log("Internet connection test failed", "WARNING")
                return False
        except Exception as e:
            self.log(f"Internet connection test failed: {e}", "WARNING")
            return False
    
    def detect_existing_installation(self):
        """Detect if GBot is already installed and analyze its state"""
        self.log("Detecting existing installation...")
        
        installation_paths = [
            self.project_root / "venv",
            self.project_root / ".env",
            self.project_root / "instance",
            self.project_root / "gbot.db",
            Path("/var/www/gbot_webapp"),
            Path("/etc/systemd/system/gbot.service"),
            Path("/etc/nginx/sites-available/gbot")
        ]
        
        existing_components = {}
        for path in installation_paths:
            if path.exists():
                existing_components[str(path)] = {
                    'exists': True,
                    'type': 'directory' if path.is_dir() else 'file',
                    'size': self._get_path_size(path),
                    'modified': self._get_path_modified(path)
                }
            else:
                existing_components[str(path)] = {'exists': False}
        
        # Check database
        db_status = self._check_database_status()
        existing_components['database'] = db_status
        
        # Check services
        service_status = self._check_service_status()
        existing_components['services'] = service_status
        
        # Check configuration files
        config_status = self._check_configuration_files()
        existing_components['configuration'] = config_status
        
        self.installation_status['existing_components'] = existing_components
        
        # Determine installation state
        if any(comp['exists'] for comp in existing_components.values() if isinstance(comp, dict) and comp.get('exists')):
            self.log("Existing installation detected", "INFO")
            self._analyze_existing_installation(existing_components)
        else:
            self.log("No existing installation found", "INFO")
        
        return existing_components
    
    def _get_path_size(self, path):
        """Get size of file or directory"""
        try:
            if path.is_file():
                return path.stat().st_size
            elif path.is_dir():
                total = 0
                for dirpath, dirnames, filenames in os.walk(path):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        if os.path.exists(filepath):
                            total += os.path.getsize(filepath)
                return total
            return 0
        except Exception:
            return 0
    
    def _get_path_modified(self, path):
        """Get last modified time of path"""
        try:
            return time.ctime(path.stat().st_mtime)
        except Exception:
            return "Unknown"
    
    def _check_database_status(self):
        """Check database connection and tables"""
        try:
            # Check SQLite database if it exists
            db_path = self.project_root / "gbot.db"
            if db_path.exists():
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = [row[0] for row in cursor.fetchall()]
                conn.close()
                
                return {
                    'exists': True,
                    'type': 'sqlite',
                    'tables': tables,
                    'path': str(db_path)
                }
            
            # Check PostgreSQL if configured
            env_file = self.project_root / ".env"
            if env_file.exists():
                # Try to parse .env file and check PostgreSQL connection
                return {
                    'exists': True,
                    'type': 'postgresql',
                    'configured': True,
                    'path': 'configured_in_env'
                }
            
            return {'exists': False}
            
        except Exception as e:
            return {'exists': False, 'error': str(e)}
    
    def _check_service_status(self):
        """Check system service status"""
        services = {}
        
        # Check systemd services
        try:
            result = subprocess.run(['systemctl', 'is-active', 'gbot'], 
                                  capture_output=True, text=True)
            services['gbot'] = result.stdout.strip()
        except Exception:
            services['gbot'] = 'unknown'
        
        # Check nginx
        try:
            result = subprocess.run(['systemctl', 'is-active', 'nginx'], 
                                  capture_output=True, text=True)
            services['nginx'] = result.stdout.strip()
        except Exception:
            services['nginx'] = 'unknown'
        
        return services
    
    def _check_configuration_files(self):
        """Check configuration file integrity"""
        config_files = {
            '.env': self.project_root / ".env",
            'config.py': self.project_root / "config.py",
            'requirements.txt': self.project_root / "requirements.txt"
        }
        
        status = {}
        for name, path in config_files.items():
            if path.exists():
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Basic validation
                    if name == '.env':
                        valid = 'SECRET_KEY' in content and 'DATABASE_URL' in content
                    elif name == 'config.py':
                        valid = 'SECRET_KEY' in content and 'SCOPES' in content
                    elif name == 'requirements.txt':
                        valid = 'Flask' in content and 'google-auth' in content
                    else:
                        valid = True
                    
                    status[name] = {
                        'exists': True,
                        'valid': valid,
                        'size': len(content)
                    }
                except Exception as e:
                    status[name] = {'exists': True, 'valid': False, 'error': str(e)}
            else:
                status[name] = {'exists': False}
        
        return status
    
    def _analyze_existing_installation(self, components):
        """Analyze the health of existing installation"""
        self.log("Analyzing existing installation...")
        
        issues = []
        warnings = []
        
        # Check database
        if 'database' in components and components['database'].get('exists'):
            db = components['database']
            if db.get('type') == 'sqlite' and 'tables' in db:
                expected_tables = ['user', 'google_account', 'google_token', 'scope', 'whitelisted_ip', 'used_domain']
                missing_tables = [t for t in expected_tables if t not in db['tables']]
                if missing_tables:
                    issues.append(f"Missing database tables: {', '.join(missing_tables)}")
        
        # Check configuration
        if 'configuration' in components:
            config = components['configuration']
            for file_name, file_status in config.items():
                if file_status.get('exists') and not file_status.get('valid'):
                    issues.append(f"Invalid configuration file: {file_name}")
        
        # Check services
        if 'services' in components:
            services = components['services']
            for service_name, status in services.items():
                if status == 'inactive':
                    warnings.append(f"Service {service_name} is inactive")
                elif status == 'failed':
                    issues.append(f"Service {service_name} has failed")
        
        if issues:
            self.log(f"Installation issues detected: {len(issues)}", "ERROR")
            for issue in issues:
                self.log(f"  - {issue}", "ERROR")
        
        if warnings:
            self.log(f"Installation warnings: {len(warnings)}", "WARNING")
            for warning in warnings:
                self.log(f"  - {warning}", "WARNING")
        
        self.installation_status['issues'] = issues
        self.installation_status['warnings'] = warnings
        
        return len(issues) == 0
    
    def create_virtual_environment(self):
        """Create Python virtual environment"""
        self.log("Creating Python virtual environment...")
        
        venv_path = self.project_root / "venv"
        
        if venv_path.exists():
            self.log("Virtual environment already exists, checking integrity...")
            
            # Check if venv is valid
            python_path = venv_path / "bin" / "python"
            if not python_path.exists():
                self.log("Existing virtual environment is corrupted, removing...", "WARNING")
                shutil.rmtree(venv_path)
            else:
                self.log("Virtual environment is valid, skipping creation")
                return True
        
        try:
            subprocess.run([sys.executable, '-m', 'venv', str(venv_path)], 
                         check=True, capture_output=True)
            self.log("Virtual environment created successfully", "SUCCESS")
            return True
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to create virtual environment: {e}", "ERROR")
            return False
    
    def install_dependencies(self):
        """Install Python dependencies"""
        self.log("Installing Python dependencies...")
        
        venv_path = self.project_root / "venv"
        pip_path = venv_path / "bin" / "pip"
        
        if not pip_path.exists():
            self.log("pip not found in virtual environment", "ERROR")
            return False
        
        try:
            # Upgrade pip first
            subprocess.run([str(pip_path), 'install', '--upgrade', 'pip'], 
                         check=True, capture_output=True)
            
            # Install requirements
            requirements_file = self.project_root / "requirements.txt"
            if requirements_file.exists():
                subprocess.run([str(pip_path), 'install', '-r', str(requirements_file)], 
                             check=True, capture_output=True)
                self.log("Dependencies installed successfully", "SUCCESS")
                return True
            else:
                self.log("requirements.txt not found", "ERROR")
                return False
                
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to install dependencies: {e}", "ERROR")
            return False
    
    def setup_database(self):
        """Setup database (SQLite for development, PostgreSQL for production)"""
        self.log("Setting up database...")
        
        # Check if database already exists and is valid
        db_path = self.project_root / "gbot.db"
        if db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = [row[0] for row in cursor.fetchall()]
                conn.close()
                
                expected_tables = ['user', 'google_account', 'google_token', 'scope', 'whitelisted_ip', 'used_domain']
                if all(table in tables for table in expected_tables):
                    self.log("Database already exists and is valid", "INFO")
                    return True
                else:
                    self.log("Database exists but is missing tables, will recreate", "WARNING")
                    db_path.unlink()
            except Exception as e:
                self.log(f"Database validation failed: {e}, will recreate", "WARNING")
                if db_path.exists():
                    db_path.unlink()
        
        try:
            # Create database tables
            from app import app, db
            with app.app_context():
                db.create_all()
                self.log("Database setup completed successfully", "SUCCESS")
                return True
        except Exception as e:
            self.log(f"Database setup failed: {e}", "ERROR")
            return False
    
    def create_environment_file(self):
        """Create environment configuration file"""
        self.log("Creating environment configuration...")
        
        env_file = self.project_root / ".env"
        
        if env_file.exists():
            self.log("Environment file already exists, checking content...")
            try:
                with open(env_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check if required variables are present
                required_vars = ['SECRET_KEY', 'WHITELIST_TOKEN']
                missing_vars = [var for var in required_vars if var not in content]
                
                if not missing_vars:
                    self.log("Environment file is complete", "INFO")
                    return True
                else:
                    self.log(f"Environment file missing variables: {missing_vars}", "WARNING")
            except Exception as e:
                self.log(f"Error reading environment file: {e}", "WARNING")
        
        try:
            # Generate secure keys
            import secrets
            secret_key = secrets.token_hex(32)
            whitelist_token = secrets.token_hex(16)
            
            env_content = f"""# GBot Web Application Environment Configuration
# Generated automatically during installation

SECRET_KEY={secret_key}
WHITELIST_TOKEN={whitelist_token}

# Database Configuration (SQLite for development)
DATABASE_URL=sqlite:///{self.project_root}/gbot.db

# Google API Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Application Settings
DEBUG=True
FLASK_ENV=development
"""
            
            with open(env_file, 'w', encoding='utf-8') as f:
                f.write(env_content)
            
            self.log("Environment file created successfully", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to create environment file: {e}", "ERROR")
            return False
    
    def validate_installation(self):
        """Validate the complete installation"""
        self.log("Validating installation...")
        
        validation_checks = {
            'virtual_environment': self._validate_virtual_environment(),
            'dependencies': self._validate_dependencies(),
            'database': self._validate_database(),
            'configuration': self._validate_configuration(),
            'application_startup': self._validate_application_startup()
        }
        
        all_valid = all(validation_checks.values())
        
        if all_valid:
            self.log("All validation checks passed", "SUCCESS")
        else:
            self.log("Some validation checks failed", "ERROR")
            for check, result in validation_checks.items():
                if not result:
                    self.log(f"  - {check}: FAILED", "ERROR")
        
        return all_valid
    
    def _validate_virtual_environment(self):
        """Validate virtual environment"""
        venv_path = self.project_root / "venv"
        if not venv_path.exists():
            return False
        
        python_path = venv_path / "bin" / "python"
        return python_path.exists()
    
    def _validate_dependencies(self):
        """Validate installed dependencies"""
        try:
            venv_path = self.project_root / "venv"
            python_path = venv_path / "bin" / "python"
            
            if not python_path.exists():
                return False
            
            # Test importing key packages
            result = subprocess.run([str(python_path), '-c', 
                                   'import flask, google.auth, sqlalchemy'], 
                                  capture_output=True)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _validate_database(self):
        """Validate database"""
        try:
            db_path = self.project_root / "gbot.db"
            if not db_path.exists():
                return False
            
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            expected_tables = ['user', 'google_account', 'google_token', 'scope', 'whitelisted_ip', 'used_domain']
            return all(table in tables for table in expected_tables)
            
        except Exception:
            return False
    
    def _validate_configuration(self):
        """Validate configuration files"""
        env_file = self.project_root / ".env"
        config_file = self.project_root / "config.py"
        
        if not env_file.exists() or not config_file.exists():
            return False
        
        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                env_content = f.read()
            
            required_vars = ['SECRET_KEY', 'WHITELIST_TOKEN']
            return all(var in env_content for var in required_vars)
            
        except Exception:
            return False
    
    def _validate_application_startup(self):
        """Validate that the application can start"""
        try:
            # Test import without starting the full app
            sys.path.insert(0, str(self.project_root))
            import app
            return True
        except Exception as e:
            self.log(f"Application startup validation failed: {e}", "WARNING")
            return False
    
    def run_installation(self, force_reinstall=False):
        """Run the complete installation process"""
        self.log("Starting GBot Web Application installation...")
        self.log(f"Installation mode: {'Force reinstall' if force_reinstall else 'Smart install'}")
        
        # Check prerequisites
        if not self.check_prerequisites():
            self.log("Prerequisites check failed. Please fix the issues and try again.", "ERROR")
            return False
        
        # Detect existing installation
        existing_components = self.detect_existing_installation()
        
        if existing_components and not force_reinstall:
            # Check if reinstallation is needed
            if self.installation_status.get('issues'):
                self.log("Issues detected in existing installation. Reinstallation recommended.", "WARNING")
                response = input("Do you want to reinstall? (y/N): ").strip().lower()
                if response == 'y':
                    force_reinstall = True
                else:
                    self.log("Installation aborted by user", "INFO")
                    return False
        
        if force_reinstall:
            self.log("Force reinstall mode - removing existing components...")
            self._cleanup_existing_installation()
        
        # Run installation steps
        installation_steps = [
            ("Creating virtual environment", self.create_virtual_environment),
            ("Installing dependencies", self.install_dependencies),
            ("Setting up database", self.setup_database),
            ("Creating environment configuration", self.create_environment_file),
            ("Validating installation", self.validate_installation)
        ]
        
        for step_name, step_function in installation_steps:
            self.log(f"Step: {step_name}")
            if not step_function():
                self.log(f"Installation failed at step: {step_name}", "ERROR")
                return False
        
        self.log("Installation completed successfully!", "SUCCESS")
        self._save_installation_status()
        self._display_post_installation_info()
        
        return True
    
    def _cleanup_existing_installation(self):
        """Clean up existing installation components"""
        self.log("Cleaning up existing installation...")
        
        components_to_remove = [
            self.project_root / "venv",
            self.project_root / "instance",
            self.project_root / "gbot.db",
            self.project_root / "__pycache__",
            self.project_root / "*.pyc"
        ]
        
        for component in components_to_remove:
            if isinstance(component, Path) and component.exists():
                if component.is_dir():
                    shutil.rmtree(component)
                else:
                    component.unlink()
                self.log(f"Removed: {component}")
        
        # Remove Python cache files
        for pyc_file in self.project_root.rglob("*.pyc"):
            pyc_file.unlink()
        
        for cache_dir in self.project_root.rglob("__pycache__"):
            shutil.rmtree(cache_dir)
    
    def _save_installation_status(self):
        """Save installation status and configuration"""
        status = {
            'installation_date': time.strftime("%Y-%m-%d %H:%M:%S"),
            'system_info': self.system_info,
            'installation_status': self.installation_status,
            'version': '1.0.0'
        }
        
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(status, f, indent=2, default=str)
        
        self.log("Installation status saved", "INFO")
    
    def _display_post_installation_info(self):
        """Display post-installation information"""
        print("\n" + "="*60)
        print("🎉 GBot Web Application Installation Complete!")
        print("="*60)
        print("\n📋 Installation Summary:")
        print(f"  • Project Directory: {self.project_root}")
        print(f"  • Virtual Environment: {self.project_root}/venv")
        print(f"  • Database: {self.project_root}/gbot.db")
        print(f"  • Configuration: {self.project_root}/.env")
        print(f"  • Log File: {self.install_log}")
        
        print("\n🚀 Next Steps:")
        print("  1. Activate the virtual environment:")
        print(f"     source {self.project_root}/venv/bin/activate")
        
        print("  2. Start the application:")
        print(f"     python {self.project_root}/app.py")
        
        print("  3. Access the application at: http://localhost:5000")
        print("  4. Default admin credentials:")
        print("     Username: admin")
        print("     Password: A9B3nX#Q8k$mZ6vw")
        
        print("\n📚 Documentation:")
        print("  • Check the README.md file for detailed usage instructions")
        print("  • Review the install.log file for installation details")
        
        print("\n🔧 Troubleshooting:")
        print("  • If you encounter issues, check the install.log file")
        print("  • Run 'python install.py --validate' to check installation health")
        print("  • Run 'python install.py --reinstall' to reinstall if needed")
        
        print("\n" + "="*60)

def main():
    """Main installation function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='GBot Web Application Installer')
    parser.add_argument('--reinstall', action='store_true', 
                       help='Force reinstallation of all components')
    parser.add_argument('--validate', action='store_true',
                       help='Validate existing installation without installing')
    parser.add_argument('--check', action='store_true',
                       help='Check system prerequisites only')
    
    args = parser.parse_args()
    
    installer = GBotInstaller()
    
    if args.check:
        installer.check_prerequisites()
        return
    
    if args.validate:
        installer.detect_existing_installation()
        if installer.validate_installation():
            print("✅ Installation validation passed")
        else:
            print("❌ Installation validation failed")
        return
    
    # Run installation
    success = installer.run_installation(force_reinstall=args.reinstall)
    
    if success:
        print("\n✅ Installation completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Installation failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
