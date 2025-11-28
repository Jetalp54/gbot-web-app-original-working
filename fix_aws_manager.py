
import os

TARGET_FILE = r"c:\Users\PC\Desktop\Gbot-original\routes\aws_manager.py"

NEW_CONTENT = r'''@aws_manager.route('/api/aws/bulk-generate', methods=['POST'])
@login_required
def bulk_generate():
    """
    Start background job to generate app passwords in bulk.
    Invokes Lambdas synchronously on the server side and saves results to DB.
    """
    data = request.get_json()
    access_key = data.get('access_key', '').strip()
    secret_key = data.get('secret_key', '').strip()
    region = data.get('region', '').strip()
    users_raw = data.get('users', [])
    
    if not users_raw:
        return jsonify({'success': False, 'error': 'No users provided'}), 400

    # Auto-clear DynamoDB before starting new batch
    try:
        session_boto = get_boto3_session(access_key, secret_key, region)
        dynamodb = session_boto.resource('dynamodb')
        table = dynamodb.Table("gbot-app-passwords")
        
        # Quick scan and delete old items
        response = table.scan()
        items = response.get('Items', [])
        if items:
            with table.batch_writer() as batch:
                for item in items:
                    batch.delete_item(Key={'email': item['email']})
            logger.info(f"[DYNAMODB] ✓ Auto-cleared {len(items)} old items before new batch")
    except Exception as e:
        logger.warning(f"[DYNAMODB] Could not auto-clear (table may not exist): {e}")
        # Continue anyway - not critical

    # Parse users
    users = []
    for u in users_raw:
        parts = u.split(':', 1)
        if len(parts) == 2:
            users.append({'email': parts[0].strip(), 'password': parts[1].strip()})
    
    if not users:
        return jsonify({'success': False, 'error': 'No valid user:password pairs found'}), 400

    logger.info(f"[BULK] Received {len(users_raw)} raw user entries, parsed {len(users)} valid users")

    # --- PROOF OF LIFE LOGGING ---
    print("\n" + "!"*80, flush=True)
    print("!!! NEW CODE LOADED - RESTORED NESTED PARALLELISM !!!", flush=True)
    print(f"!!! TIMESTAMP: {time.time()} !!!", flush=True)
    print("!"*80 + "\n", flush=True)
    # -----------------------------

    job_id = str(int(time.time()))
    with jobs_lock:
        active_jobs[job_id] = {
            'total': len(users),
            'completed': 0,
            'success': 0,
            'failed': 0,
            'results': [],
            'status': 'processing'
        }
        # Save to file for other workers
        save_jobs({job_id: active_jobs[job_id]})
    
    logger.info(f"[BULK] Created job {job_id} for {len(users)} users")

    # Start background thread
    # We pass app_context explicitly if needed, but db operations need app context inside the thread
    from app import app
    
    def background_process(app, job_id, users, access_key, secret_key, region):
        """Background process to handle bulk user processing across geos"""
        # --- PROOF OF LIFE LOGGING ---
        print("\n" + "!"*80, flush=True)
        print(f"!!! BACKGROUND PROCESS STARTED - NESTED PARALLELISM - Job {job_id} !!!", flush=True)
        print("!"*80 + "\n", flush=True)
        # -----------------------------

        logger.info(f"[BULK] ========== BACKGROUND PROCESS STARTED ==========")
        logger.info(f"[BULK] Job ID: {job_id}")
        logger.info(f"[BULK] Total users: {len(users)}")
        logger.info(f"[BULK] Region: {region}")
        
        # Ensure job exists before starting processing
        with jobs_lock:
            if job_id not in active_jobs:
                logger.error(f"[BULK] Job {job_id} not found in active_jobs at start of background_process!")
                # Try to recreate it
                active_jobs[job_id] = {
                    'total': len(users),
                    'completed': 0,
                    'success': 0,
                    'failed': 0,
                    'results': [],
                    'status': 'processing'
                }
                logger.info(f"[BULK] Recreated job {job_id}")
            else:
                logger.info(f"[BULK] Job {job_id} found in active_jobs")
        
        try:
            logger.info(f"[BULK] Entering app context...")
            with app.app_context():
                logger.info(f"[BULK] App context entered successfully")
                # Pre-detect Lambda functions across ALL geos
                # This is necessary because functions are distributed across multiple AWS regions
                lambda_functions = []
                # We no longer pre-detect Lambda functions across all regions
                # Instead, we'll look for functions in their assigned regions during processing
                logger.info(f"[BULK] Will process users using geo-distributed Lambda functions")
                
                # NEW LOGIC: Calculate total functions based on user count
                # Distribute functions evenly across ALL available geos
                # Process functions sequentially within each geo
                
                import math
                
                USERS_PER_FUNCTION = 10  # Fixed: Each function handles exactly 10 users
                
                # Calculate total number of functions needed
                total_users = len(users)
                num_functions = math.ceil(total_users / USERS_PER_FUNCTION)
                
                logger.info("=" * 60)
                logger.info(f"[BULK] Function Calculation")
                logger.info(f"[BULK] Total users: {total_users}")
                logger.info(f"[BULK] Users per function: {USERS_PER_FUNCTION}")
                logger.info(f"[BULK] Total functions needed: {num_functions}")
                logger.info("=" * 60)
                
                # Get all available AWS regions (geos)
                # These are all AWS regions where Lambda can be deployed
                # Use the global constant we defined earlier
                # AVAILABLE_GEO_REGIONS is already defined in the module scope
                
                # Distribute functions evenly across all available geos using round-robin
                # Example: 17 functions, 23 geos → 1 function per geo (first 17 geos get 1 function each)
                # Example: 50 functions, 23 geos → ~2-3 functions per geo (distributed evenly)
                functions_per_geo = {}  # {geo: [list of function_numbers]}
                
                for func_num in range(num_functions):
                    # Round-robin distribution: function 0 → geo 0, function 1 → geo 1, etc.
                    geo_index = func_num % len(AVAILABLE_GEO_REGIONS)
                    geo = AVAILABLE_GEO_REGIONS[geo_index]
                    
                    if geo not in functions_per_geo:
                        functions_per_geo[geo] = []
                    functions_per_geo[geo].append(func_num + 1)  # Function numbers start at 1
                
                logger.info("=" * 60)
                logger.info(f"[BULK] Function Distribution Across Geos")
                logger.info(f"[BULK] Total functions: {num_functions}")
                logger.info(f"[BULK] Available geos: {len(AVAILABLE_GEO_REGIONS)}")
                logger.info(f"[BULK] Functions per geo:")
                for geo, func_numbers in sorted(functions_per_geo.items()):
                    logger.info(f"[BULK]   - {geo}: {len(func_numbers)} function(s) {func_numbers}")
                logger.info("=" * 60)
                
                # Split users into batches of 10, assigning each batch to a function
                # Function 1 gets users 0-9, Function 2 gets users 10-19, etc.
                # CRITICAL: Each batch MUST be exactly 10 users or less
                user_batches = []  # List of (function_number, geo, user_batch) tuples
                logger.info(f"[BULK] Creating batches: total_users={total_users}, num_functions={num_functions}, USERS_PER_FUNCTION={USERS_PER_FUNCTION}")
                for func_num in range(num_functions):
                    start_idx = func_num * USERS_PER_FUNCTION
                    end_idx = min(start_idx + USERS_PER_FUNCTION, total_users)
                    batch_users = users[start_idx:end_idx]
                
                    # ENFORCE: Ensure batch never exceeds 10 users
                    if len(batch_users) > USERS_PER_FUNCTION:
                        logger.error(f"[BULK] ⚠️ CRITICAL: Batch {func_num + 1} has {len(batch_users)} users, exceeding limit of {USERS_PER_FUNCTION}! Truncating...")
                        batch_users = batch_users[:USERS_PER_FUNCTION]
                    
                    if batch_users:
                        # Determine which geo this function belongs to
                        geo_index = func_num % len(AVAILABLE_GEO_REGIONS)
                        geo = AVAILABLE_GEO_REGIONS[geo_index]
                        user_batches.append((func_num + 1, geo, batch_users))
                        logger.info(f"[BULK] Function {func_num + 1} ({geo}) will process {len(batch_users)} user(s) (MAX: {USERS_PER_FUNCTION}): {[u['email'] for u in batch_users[:3]]}{'...' if len(batch_users) > 3 else ''}")
                        if len(batch_users) > USERS_PER_FUNCTION:
                            logger.error(f"[BULK] ⚠️ ERROR: Function {func_num + 1} batch size {len(batch_users)} exceeds limit {USERS_PER_FUNCTION}!")
                    else:
                        logger.warning(f"[BULK] Function {func_num + 1} has empty batch (start_idx={start_idx}, end_idx={end_idx}, total_users={total_users})")
                
                # BATCH PROCESSING: Process 10 users at a time, sequentially within each geo
                USERS_PER_BATCH = 10
                
                def process_user_batch_sync(user_batch, assigned_function_name, lambda_region=None):
                    """
                    Process a batch of up to 10 users synchronously (wait for completion).
                    Returns list of results, one per user.
                    This is used for sequential processing within each geo.
                
                    Args:
                        user_batch: List of user dicts to process (MUST be <= 10 users)
                        assigned_function_name: Name of Lambda function to invoke
                        lambda_region: AWS region where Lambda function is deployed (defaults to 'region' variable)
                    """
                    with app.app_context():
                        # CRITICAL: Enforce 10-user limit
                        MAX_USERS_PER_BATCH = 10
                        if len(user_batch) > MAX_USERS_PER_BATCH:
                            logger.error(f"[BULK] [{assigned_function_name}] ⚠️ CRITICAL ERROR: Batch has {len(user_batch)} users, exceeding limit of {MAX_USERS_PER_BATCH}!")
                            logger.error(f"[BULK] [{assigned_function_name}] Truncating batch to {MAX_USERS_PER_BATCH} users")
                            user_batch = user_batch[:MAX_USERS_PER_BATCH]
                        
                        # Use lambda_region if provided, otherwise fall back to user's selected region
                        target_region = lambda_region if lambda_region else region
                        
                        # Create INDEPENDENT boto3 session and clients for this batch
                        session_batch = boto3.Session(
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key,
                            region_name=target_region
                        )
                        
                        # Each batch gets its own Lambda client with extended timeout
                        # CRITICAL: Set read_timeout to 1000 seconds (16+ minutes) to handle batch processing
                        # Lambda timeout is 900 seconds, so we need client timeout > Lambda timeout
                        # IMPORTANT: Lambda client uses the region from session_batch (target_region)
                        lam_batch = session_batch.client("lambda", config=Config(
                            max_pool_connections=10,
                            retries={'max_attempts': 0},
                            read_timeout=1000,  # 16+ minutes - must exceed Lambda timeout (900s)
                            connect_timeout=60  # 60 seconds connection timeout
                        ))
                        
                        # Each batch gets its own DynamoDB resource
                        dynamodb_batch = session_batch.resource('dynamodb', config=Config(
                            max_pool_connections=10
                        ))
                        table_batch = dynamodb_batch.Table("gbot-app-passwords")
                    
                        # Prepare all users for processing - NO pre-filtering
                        # Lambda will handle deduplication if needed
                        batch_results = []
                        users_to_process = user_batch  # Process ALL users in the batch (already limited to 10)
                    
                        # Final validation before sending to Lambda
                        if len(users_to_process) > MAX_USERS_PER_BATCH:
                            logger.error(f"[BULK] [{assigned_function_name}] ⚠️ FINAL CHECK FAILED: {len(users_to_process)} users exceeds {MAX_USERS_PER_BATCH} limit!")
                            users_to_process = users_to_process[:MAX_USERS_PER_BATCH]
                        
                        logger.info(f"[BULK] [{assigned_function_name}] Will process {len(users_to_process)} user(s) in batch (MAX: {MAX_USERS_PER_BATCH})")
                    
                        # Mark emails as being processed (for duplicate detection across parallel geos)
                        for user in users_to_process:
                            email = user['email']
                            with processing_lock:
                                if email in processing_emails:
                                    logger.warning(f"[BULK] ⚠️ WARNING: {email} is already being processed in another geo!")
                                processing_emails.add(email)
                    
                        # Prepare batch payload for Lambda
                        # CRITICAL: Final check - ensure we never send more than 10 users
                        MAX_USERS_PER_BATCH = 10
                        if len(users_to_process) > MAX_USERS_PER_BATCH:
                            logger.error(f"[BULK] [{assigned_function_name}] ⚠️ PAYLOAD CHECK: Truncating {len(users_to_process)} users to {MAX_USERS_PER_BATCH}")
                            users_to_process = users_to_process[:MAX_USERS_PER_BATCH]
                        
                        batch_payload = {
                            "users": [
                                {"email": u['email'], "password": u['password']}
                                for u in users_to_process
                            ]
                        }
                        
                        logger.info("=" * 60)
                        logger.info(f"[BULK] [{assigned_function_name}] PREPARING TO INVOKE LAMBDA")
                        logger.info(f"[BULK] [{assigned_function_name}] Batch size: {len(users_to_process)} user(s) (MAX: {MAX_USERS_PER_BATCH})")
                        if len(users_to_process) > MAX_USERS_PER_BATCH:
                            logger.error(f"[BULK] [{assigned_function_name}] ⚠️ ERROR: Batch size {len(users_to_process)} exceeds limit {MAX_USERS_PER_BATCH}!")
                        logger.info(f"[BULK] [{assigned_function_name}] Users in batch: {[u['email'] for u in users_to_process]}")
                        logger.info(f"[BULK] [{assigned_function_name}] Payload structure: {{'users': [{{'email': ..., 'password': ...}}]}}")
                        logger.info(f"[BULK] [{assigned_function_name}] Payload JSON length: {len(json.dumps(batch_payload))} bytes")
                        logger.info(f"[BULK] [{assigned_function_name}] Payload preview: {json.dumps(batch_payload)[:500]}...")
                        logger.info("=" * 60)
                        
                        # Rate limiting: Acquire semaphore to limit concurrent invocations
                        # NOTE: Semaphore limit is now 500 to allow all functions in all geos to start in parallel
                        # The semaphore is held for the duration of the Lambda invocation (up to 15 minutes)
                        # This ensures we don't exceed AWS account limits while allowing maximum parallelism
                        logger.info(f"[BULK] [{assigned_function_name}] Acquiring semaphore for Lambda invocation...")
                        lambda_invocation_semaphore.acquire()
                        logger.info(f"[BULK] [{assigned_function_name}] ✓ Semaphore acquired, invoking Lambda NOW (parallel execution enabled)")
                        try:
                            # Retry logic for rate limiting
                            max_retries = 3
                            resp = None
                            for attempt in range(max_retries):
                                try:
                                    # Use SYNC invocation to wait for completion (sequential processing)
                                    resp = lam_batch.invoke(
                                        FunctionName=assigned_function_name,
                                        InvocationType="RequestResponse",  # SYNC - wait for completion
                                        Payload=json.dumps(batch_payload).encode("utf-8"),
                                    )
                                
                                    # Parse Lambda response
                                    payload = resp.get("Payload")
                                    body = payload.read().decode("utf-8") if payload else "{}"
                                    logger.info("=" * 60)
                                    logger.info(f"[BULK] [{assigned_function_name}] LAMBDA RESPONSE RECEIVED")
                                    logger.info(f"[BULK] [{assigned_function_name}] Response status code: {resp.get('StatusCode')}")
                                    logger.info(f"[BULK] [{assigned_function_name}] Response body (first 2000 chars): {body[:2000]}")
                                    logger.info("=" * 60)
                                
                                    try:
                                        lambda_response = json.loads(body)
                                    except json.JSONDecodeError as je:
                                        logger.error(f"[BULK] Failed to parse Lambda response as JSON: {je}")
                                        # All users in batch fail
                                        for u in users_to_process:
                                            batch_results.append({
                                                'email': u['email'],
                                                'success': False,
                                                'error': f'Invalid JSON response: {body[:200]}'
                                            })
                                        return batch_results
                                
                                    # Handle batch response format
                                    if lambda_response.get("status") == "completed" and "results" in lambda_response:
                                        # Batch processing response
                                        lambda_results = lambda_response.get("results", [])
                                        logger.info(f"[BULK] [{assigned_function_name}] Lambda returned {len(lambda_results)} results for {len(users_to_process)} users sent")
                                        for lambda_result in lambda_results:
                                            email = lambda_result.get("email", "unknown")
                                            lambda_status = lambda_result.get("status", "unknown")
                                            app_password = lambda_result.get("app_password")
                                            error_msg = lambda_result.get("error_message", "Unknown error")
                                        
                                            if lambda_status == 'success' and app_password:
                                                logger.info(f"[BULK] Saving password for {email} to DB")
                                                try:
                                                    save_app_password(email, app_password)
                                                    logger.info(f"[BULK] ✓ Successfully processed {email}")
                                                except Exception as db_err:
                                                    logger.error(f"[BULK] Failed to save to DB for {email}: {db_err}")
                                                batch_results.append({
                                                    'email': email,
                                                    'success': True,
                                                    'app_password': app_password
                                                })
                                            else:
                                                logger.warning(f"[BULK] ✗ Lambda failed for {email}: {error_msg}")
                                                batch_results.append({
                                                    'email': email,
                                                    'success': False,
                                                    'error': error_msg
                                                })
                                        break  # Success, exit retry loop
                                    else:
                                        # Fallback: single user response format (backward compatibility)
                                        lambda_status = lambda_response.get('status', 'unknown')
                                        app_password = lambda_response.get('app_password')
                                        error_msg = lambda_response.get('error_message', 'Unknown error')
                                    
                                        # If only one user in batch, use single response format
                                        if len(users_to_process) == 1:
                                            email = users_to_process[0]['email']
                                            if lambda_status == 'success' and app_password:
                                                try:
                                                    save_app_password(email, app_password)
                                                    logger.info(f"[BULK] ✓ Successfully processed {email}")
                                                except Exception as db_err:
                                                    logger.error(f"[BULK] Failed to save to DB for {email}: {db_err}")
                                                batch_results.append({
                                                    'email': email,
                                                    'success': True,
                                                    'app_password': app_password
                                                })
                                            else:
                                                batch_results.append({
                                                    'email': email,
                                                    'success': False,
                                                    'error': error_msg
                                                })
                                            break  # Success, exit retry loop
                                        else:
                                            # Multiple users but got single response - all fail
                                            logger.error(f"[BULK] Expected batch response but got single user format")
                                            for u in users_to_process:
                                                batch_results.append({
                                                    'email': u['email'],
                                                    'success': False,
                                                    'error': 'Invalid response format from Lambda'
                                                })
                                            return batch_results
                                    
                                except ClientError as ce:
                                    error_code = ce.response['Error']['Code']
                                    error_message = ce.response['Error'].get('Message', '')
                                    
                                    if error_code == 'ResourceNotFoundException':
                                        logger.error(f"[BULK] Lambda function {assigned_function_name} not found")
                                        # Try to fall back to default function
                                        if assigned_function_name != PRODUCTION_LAMBDA_NAME:
                                            logger.warning(f"[BULK] Falling back to default function {PRODUCTION_LAMBDA_NAME}")
                                            assigned_function_name = PRODUCTION_LAMBDA_NAME
                                            continue  # Retry with default function
                                        else:
                                            # All users in batch fail
                                            for u in users_to_process:
                                                batch_results.append({
                                                    'email': u['email'],
                                                    'success': False,
                                                    'error': f'Lambda function {assigned_function_name} not found'
                                                })
                                            return batch_results
                                    
                                    if error_code == 'TooManyRequestsException' or error_code == 'ThrottlingException':
                                        if attempt < max_retries - 1:
                                            base_wait = (2 ** attempt) * 2
                                            jitter = random.uniform(0, 1)
                                            wait_time = base_wait + jitter
                                            logger.warning(f"[BULK] Rate limited for batch, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{max_retries})")
                                            time.sleep(wait_time)
                                        else:
                                            # All users in batch fail
                                            for u in users_to_process:
                                                batch_results.append({
                                                    'email': u['email'],
                                                    'success': False,
                                                    'error': f'Rate limited: {error_message}'
                                                })
                                            return batch_results
                                    else:
                                        logger.error(f"[BULK] AWS error: {error_code} - {error_message}")
                                        # All users in batch fail
                                        for u in users_to_process:
                                            batch_results.append({
                                                'email': u['email'],
                                                'success': False,
                                                'error': f'AWS Error ({error_code}): {error_message}'
                                            })
                                        return batch_results
                                except Exception as invoke_err:
                                    # Check if it's a timeout error
                                    if 'Read timeout' in str(invoke_err) or 'timeout' in str(invoke_err).lower():
                                        logger.error(f"[BULK] Read timeout on attempt {attempt + 1} - Lambda may still be processing")
                                        if attempt == max_retries - 1:
                                            # Final attempt failed - mark as timeout
                                            for u in users_to_process:
                                                batch_results.append({
                                                    'email': u['email'],
                                                    'success': False,
                                                    'error': f'Read timeout - Lambda processing may have exceeded timeout'
                                                })
                                            return batch_results
                                        time.sleep(5)
                                        continue
                                    else:
                                        logger.error(f"[BULK] Invocation error: {invoke_err}")
                                        if attempt == max_retries - 1:
                                            # Final attempt failed
                                            for u in users_to_process:
                                                batch_results.append({
                                                    'email': u['email'],
                                                    'success': False,
                                                    'error': f'Invocation error: {str(invoke_err)}'
                                                })
                                            return batch_results
                                        time.sleep(2)
                                        continue
                        finally:
                            lambda_invocation_semaphore.release()
                        
                        # Remove processed emails from tracking set
                        for u in users_to_process:
                            with processing_lock:
                                processing_emails.discard(u['email'])
                    
                        return batch_results
            
                # Group batches by geo for sequential processing within each geo
                batches_by_geo = {}  # {geo: [(function_number, user_batch), ...]}
                logger.info(f"[BULK] Grouping {len(user_batches)} batches by geo...")
                for func_num, geo, batch_users in user_batches:
                    logger.info(f"[BULK] Processing batch: func_num={func_num}, geo={geo}, batch_size={len(batch_users)}, users={[u['email'] for u in batch_users[:3]]}{'...' if len(batch_users) > 3 else ''}")
                    if geo not in batches_by_geo:
                        batches_by_geo[geo] = []
                    batches_by_geo[geo].append((func_num, batch_users))
                    logger.info(f"[BULK] Added to geo {geo}: Function {func_num} with {len(batch_users)} user(s)")
            
                logger.info("=" * 60)
                logger.info(f"[BULK] Batches per geo:")
                for geo, geo_batches in sorted(batches_by_geo.items()):
                    total_users_in_geo = sum(len(batch) for _, batch in geo_batches)
                    logger.info(f"[BULK]   - {geo}: {len(geo_batches)} function(s), {total_users_in_geo} user(s)")
                logger.info(f"[BULK] TOTAL GEOS TO PROCESS: {len(batches_by_geo)}")
                logger.info(f"[BULK] Geo list: {list(batches_by_geo.keys())}")
                logger.info("=" * 60)
            
                def process_geo_parallel(geo, geo_batches_list):
                    """
                    Process all batches in a geo in PARALLEL (multiple functions at the same time).
                    Creates Lambda functions as needed and processes them concurrently.
                    Maximum 10 functions per geo at the same time (AWS Lambda concurrency limit).
                    Minimum 2 functions per geo at the same time (as requested).
                    """
                    try:
                        logger.info("=" * 60)
                        logger.info(f"[BULK] [{geo}] ===== STARTING PARALLEL PROCESSING =====")
                        logger.info(f"[BULK] [{geo}] Total functions to process: {len(geo_batches_list)}")
                        logger.info(f"[BULK] [{geo}] Function numbers: {[func_num for func_num, _ in geo_batches_list]}")
                        
                        # Calculate max workers: min(10, number of functions, but at least 2 if we have 2+ functions)
                        max_workers = min(10, len(geo_batches_list))
                        if len(geo_batches_list) >= 2 and max_workers < 2:
                            max_workers = 2
                        logger.info(f"[BULK] [{geo}] Will process {max_workers} function(s) in parallel (max 10 per geo)")
                        logger.info("=" * 60)
                        
                        # Create boto3 session for this geo (use the geo's region)
                        try:
                            logger.info(f"[BULK] [{geo}] Creating boto3 session for region: {geo}")
                            session_boto = boto3.Session(
                                aws_access_key_id=access_key,
                                aws_secret_access_key=secret_key,
                                region_name=geo  # Use geo as the region
                            )
                            
                            # Verify credentials work for this region
                            try:
                                sts = session_boto.client('sts')
                                identity = sts.get_caller_identity()
                                logger.info(f"[BULK] [{geo}] ✓ Credentials verified. Account: {identity.get('Account')}")
                            except Exception as sts_err:
                                logger.error(f"[BULK] [{geo}] ✗✗✗ CRITICAL: Credential verification failed: {sts_err}")
                                logger.error(traceback.format_exc())
                                raise Exception(f"Credential verification failed for {geo}: {sts_err}")
                            
                            lam_client = session_boto.client("lambda", config=Config(
                                max_pool_connections=10,
                                retries={'max_attempts': 3}
                            ))
                            
                            logger.info(f"[BULK] [{geo}] Listing Lambda functions in region {geo}...")
                            all_functions = lam_client.list_functions()
                            existing_function_names = [fn['FunctionName'] for fn in all_functions.get('Functions', [])]
                            logger.info(f"[BULK] [{geo}] ✓ Found {len(existing_function_names)} existing function(s) in {geo}: {existing_function_names[:5]}{'...' if len(existing_function_names) > 5 else ''}")
                        except Exception as e:
                            logger.error(f"[BULK] [{geo}] ✗✗✗ CRITICAL ERROR: Could not initialize session or list functions: {e}")
                            logger.error(traceback.format_exc())
                            # Don't return empty - raise exception so it's caught by outer handler
                            raise Exception(f"Failed to initialize {geo}: {e}")
                        
                        # Helper function to process a single function
                        def process_single_function(func_num, batch_users, batch_idx):
                            """Process a single Lambda function (thread-safe)"""
                            function_results = []
                            func_name = None
                            
                            try:
                                logger.info("=" * 60)
                                logger.info(f"[BULK] [{geo}] ===== FUNCTION {batch_idx + 1}/{len(geo_batches_list)} (PARALLEL) =====")
                                logger.info(f"[BULK] [{geo}] Function number: {func_num}")
                                logger.info(f"[BULK] [{geo}] Users in batch: {len(batch_users)}")
                                logger.info(f"[BULK] [{geo}] User emails: {[u['email'] for u in batch_users[:5]]}{'...' if len(batch_users) > 5 else ''}")
                                logger.info("=" * 60)
                            
                                # Generate function name: edu-gw-chromium-{geo_code}-{func_num}
                                geo_code = geo.replace('-', '')  # Remove dashes: us-east-1 -> useast1
                                func_name = f"{PRODUCTION_LAMBDA_NAME}-{geo_code}-{func_num}"
                                
                                logger.info(f"[BULK] [{geo}] Looking for function: {func_name}")
                                logger.info(f"[BULK] [{geo}] Available functions in {geo}: {existing_function_names}")
                            
                                # Create function if it doesn't exist (thread-safe check)
                                with threading.Lock():
                                    if func_name not in existing_function_names:
                                        # Try to find any function matching the pattern
                                        matching_functions = [fn for fn in existing_function_names if PRODUCTION_LAMBDA_NAME in fn and geo_code in fn]
                                        if matching_functions:
                                            logger.warning(f"[BULK] [{geo}] Function {func_name} not found, but found similar: {matching_functions}")
                                            # Use the first matching function if exact match not found
                                            if len(matching_functions) == 1:
                                                func_name = matching_functions[0]
                                                logger.info(f"[BULK] [{geo}] Using similar function: {func_name}")
                                            else:
                                                # Multiple matches - try to find one with func_num
                                                func_num_str = str(func_num)
                                                exact_match = [fn for fn in matching_functions if func_num_str in fn]
                                                if exact_match:
                                                    func_name = exact_match[0]
                                                    logger.info(f"[BULK] [{geo}] Using function with matching number: {func_name}")
                                                else:
                                                    func_name = matching_functions[0]
                                                    logger.warning(f"[BULK] [{geo}] Using first matching function: {func_name}")
                                        else:
                                            logger.info(f"[BULK] [{geo}] Creating Lambda function: {func_name}")
                                        try:
                                            role_arn = ensure_lambda_role(session_boto)
                                            chromium_env = {
                                                "DYNAMODB_TABLE_NAME": "gbot-app-passwords",
                                                "DYNAMODB_REGION": "eu-west-1",
                                                "APP_PASSWORDS_S3_BUCKET": S3_BUCKET_NAME,
                                                "APP_PASSWORDS_S3_KEY": "app-passwords.txt",
                                            }
                                            
                                            # Add proxy configuration if enabled
                                            proxy_config = get_proxy_config()
                                            if proxy_config and proxy_config.get('enabled'):
                                                proxies = parse_proxy_list(proxy_config.get('proxies', ''))
                                                if proxies:
                                                    chromium_env['PROXY_ENABLED'] = 'true'
                                                    chromium_env['PROXY_LIST'] = proxy_config.get('proxies', '')
                                                    logger.info(f"[PROXY] [{geo}] Proxy feature enabled with {len(proxies)} proxy/proxies")
                                                else:
                                                    chromium_env['PROXY_ENABLED'] = 'false'
                                            else:
                                                chromium_env['PROXY_ENABLED'] = 'false'
                                            
                                            # Add 2Captcha configuration if enabled
                                            twocaptcha_config = get_twocaptcha_config()
                                            if twocaptcha_config and twocaptcha_config.get('enabled') and twocaptcha_config.get('api_key'):
                                                chromium_env['TWOCAPTCHA_ENABLED'] = 'true'
                                                chromium_env['TWOCAPTCHA_API_KEY'] = twocaptcha_config.get('api_key', '')
                                                logger.info(f"[2CAPTCHA] [{geo}] 2Captcha feature enabled for automatic CAPTCHA solving")
                                            else:
                                                chromium_env['TWOCAPTCHA_ENABLED'] = 'false'
                                                chromium_env['TWOCAPTCHA_API_KEY'] = ''
                                        
                                            # Extract ECR URI
                                            ecr_uri = None
                                            try:
                                                if existing_function_names:
                                                    existing_func = lam_client.get_function(FunctionName=existing_function_names[0])
                                                    code_location = existing_func.get('Code', {}).get('ImageUri')
                                                    if code_location:
                                                        ecr_uri = code_location
                                            except Exception:
                                                pass
                                        
                                            if not ecr_uri:
                                                sts = session_boto.client('sts')
                                                account_id = sts.get_caller_identity()['Account']
                                                ecr_uri = f"{account_id}.dkr.ecr.{geo}.amazonaws.com/{ECR_REPO_NAME}:{ECR_IMAGE_TAG}"
                                        
                                            if func_name != PRODUCTION_LAMBDA_NAME:
                                                create_or_update_lambda(
                                                    session=session_boto,
                                                    function_name=func_name,
                                                    role_arn=role_arn,
                                                    timeout=900,
                                                    env_vars=chromium_env,
                                                    package_type="Image",
                                                    image_uri=ecr_uri,
                                                )
                                                logger.info(f"[BULK] [{geo}] ✓ Created Lambda function: {func_name}")
                                                existing_function_names.append(func_name)
                                        except Exception as create_err:
                                            logger.error(f"[BULK] [{geo}] Failed to create {func_name}: {create_err}")
                                            func_name = PRODUCTION_LAMBDA_NAME
                                
                                # Verify function exists
                                try:
                                    all_functions_refresh = lam_client.list_functions()
                                    existing_function_names_refresh = [fn['FunctionName'] for fn in all_functions_refresh.get('Functions', [])]
                                    
                                    if func_name not in existing_function_names_refresh:
                                        logger.error(f"[BULK] [{geo}] ✗ Function {func_name} NOT FOUND in region {geo}!")
                                        for u in batch_users:
                                            function_results.append({
                                                'email': u['email'],
                                                'success': False,
                                                'error': f'Lambda function {func_name} not found in region {geo}'
                                            })
                                        return function_results
                                    
                                    logger.info(f"[BULK] [{geo}] ✓ Verified function exists: {func_name}")
                                except Exception as check_err:
                                    logger.warning(f"[BULK] [{geo}] Could not verify function existence: {check_err}, proceeding anyway...")
                                
                                # Invoke Lambda function
                                logger.info(f"[BULK] [{geo}] Invoking Lambda function: {func_name} in region: {geo}")
                                batch_results = process_user_batch_sync(batch_users, func_name, lambda_region=geo)
                                function_results.extend(batch_results)
                                logger.info(f"[BULK] [{geo}] ✓ Function {func_num} completed: {sum(1 for r in batch_results if r['success'])}/{len(batch_results)} success")
                                
                            except Exception as func_err:
                                logger.error(f"[BULK] [{geo}] ✗ Function {func_num} ({func_name}) failed: {func_err}")
                                logger.error(traceback.format_exc())
                                for u in batch_users:
                                    function_results.append({
                                        'email': u['email'],
                                        'success': False,
                                        'error': f'Function invocation failed: {str(func_err)}'
                                    })
                            
                            return function_results
                        
                        # Process all functions in PARALLEL using ThreadPoolExecutor
                        geo_results = []
                        with ThreadPoolExecutor(max_workers=max_workers) as function_pool:
                            # Submit all functions for parallel processing
                            function_futures = {}
                            for batch_idx, (func_num, batch_users) in enumerate(geo_batches_list):
                                future = function_pool.submit(process_single_function, func_num, batch_users, batch_idx)
                                function_futures[future] = (func_num, batch_idx)
                                logger.info(f"[BULK] [{geo}] ✓ Submitted function {func_num} for parallel processing")
                            
                            # Wait for all functions to complete and collect results
                            for future in as_completed(function_futures):
                                func_num, batch_idx = function_futures[future]
                                try:
                                    function_results = future.result()
                                    geo_results.extend(function_results)
                                    
                                    # Update job status
                                    with jobs_lock:
                                        if job_id in active_jobs:
                                            for result in function_results:
                                                active_jobs[job_id]['completed'] += 1
                                                if result.get('success'):
                                                    active_jobs[job_id]['success'] += 1
                                                    active_jobs[job_id]['results'].append({
                                                        'email': result['email'],
                                                        'app_password': result.get('app_password'),
                                                        'success': True
                                                    })
                                                else:
                                                    active_jobs[job_id]['failed'] += 1
                                                    active_jobs[job_id]['results'].append({
                                                        'email': result['email'],
                                                        'error': result.get('error', 'Unknown error'),
                                                        'success': False
                                                    })
                                    
                                    logger.info(f"[BULK] [{geo}] ✓ Function {func_num} finished: {sum(1 for r in function_results if r.get('success'))}/{len(function_results)} success")
                                except Exception as e:
                                    logger.error(f"[BULK] [{geo}] ✗ Function {func_num} exception: {e}")
                                    logger.error(traceback.format_exc())
                        
                        # Log completion summary
                        logger.info("=" * 60)
                        logger.info(f"[BULK] [{geo}] ===== PARALLEL PROCESSING COMPLETED =====")
                        logger.info(f"[BULK] [{geo}] Total functions processed: {len(geo_batches_list)}")
                        logger.info(f"[BULK] [{geo}] Total users processed: {len(geo_results)}")
                        logger.info(f"[BULK] [{geo}] Success: {sum(1 for r in geo_results if r.get('success'))}")
                        logger.info(f"[BULK] [{geo}] Failed: {sum(1 for r in geo_results if not r.get('success'))}")
                        logger.info("=" * 60)
                        return geo_results
                    except Exception as geo_err:
                        logger.error("=" * 60)
                        logger.error(f"[BULK] [{geo}] ✗✗✗ CRITICAL ERROR in process_geo_parallel: {geo_err}")
                        logger.error(f"[BULK] [{geo}] Error type: {type(geo_err).__name__}")
                        logger.error(f"[BULK] [{geo}] Error message: {str(geo_err)}")
                        logger.error(f"[BULK] [{geo}] Traceback: {traceback.format_exc()}")
                        logger.error("=" * 60)
                        # Return empty results with error info so other geos can continue
                        # But mark all users in this geo as failed
                        failed_results = []
                        for func_num, batch_users in geo_batches_list:
                            for u in batch_users:
                                failed_results.append({
                                    'email': u['email'],
                                    'success': False,
                                    'error': f'Geo processing failed for {geo}: {str(geo_err)}'
                                })
                        logger.error(f"[BULK] [{geo}] Returning {len(failed_results)} failed results for {geo}")
                        return failed_results
            
                # Process ALL geos in parallel (each geo processes its functions in parallel internally)
                logger.info("=" * 60)
                logger.info(f"[BULK] ===== STARTING PARALLEL GEO PROCESSING =====")
                logger.info(f"[BULK] Total users: {total_users}")
                logger.info(f"[BULK] Total functions: {num_functions}")
                logger.info(f"[BULK] Number of geos: {len(batches_by_geo)}")
                logger.info(f"[BULK] Users per function: {USERS_PER_FUNCTION}")
                logger.info(f"[BULK] Geos to process: {list(batches_by_geo.keys())}")
                logger.info("=" * 60)
            
                # Process ALL geos in parallel (each geo processes functions in parallel internally)
                max_geo_workers = len(batches_by_geo)  # One worker per geo - ALL geos process in parallel
                logger.info("=" * 60)
                logger.info(f"[BULK] ===== STARTING PARALLEL GEO PROCESSING =====")
                logger.info(f"[BULK] Total geos to process: {len(batches_by_geo)}")
                logger.info(f"[BULK] Geos: {list(batches_by_geo.keys())}")
                logger.info(f"[BULK] Max geo workers: {max_geo_workers}")
                logger.info("=" * 60)
            
                # Collect all results from all geos
                all_geo_results = []
                
                with ThreadPoolExecutor(max_workers=max_geo_workers) as geo_pool:
                    # Submit ALL geos for processing in parallel
                    geo_futures = {}
                    submitted_geos = []
                    for geo, geo_batches_list in batches_by_geo.items():
                        try:
                            logger.info(f"[BULK] ✓ Submitting geo {geo} with {len(geo_batches_list)} function(s) to thread pool")
                            future = geo_pool.submit(process_geo_parallel, geo, geo_batches_list)
                            geo_futures[future] = geo
                            submitted_geos.append(geo)
                            logger.info(f"[BULK] ✓✓✓ Successfully submitted geo {geo} to thread pool")
                        except Exception as submit_err:
                            logger.error(f"[BULK] ✗✗✗ FAILED to submit geo {geo} to thread pool: {submit_err}")
                            logger.error(traceback.format_exc())
                            # Add failed results for this geo
                            for func_num, batch_users in geo_batches_list:
                                for u in batch_users:
                                    all_geo_results.append({
                                        'email': u['email'],
                                        'success': False,
                                        'error': f'Failed to submit geo {geo} to thread pool: {str(submit_err)}'
                                    })
                
                    logger.info("=" * 60)
                    logger.info(f"[BULK] ✓✓✓ SUBMISSION SUMMARY")
                    logger.info(f"[BULK] Total geos to process: {len(batches_by_geo)}")
                    logger.info(f"[BULK] Successfully submitted: {len(submitted_geos)} geo(s)")
                    logger.info(f"[BULK] Submitted geos: {submitted_geos}")
                    logger.info(f"[BULK] Futures created: {len(geo_futures)}")
                    logger.info(f"[BULK] All geos should now be processing simultaneously")
                    logger.info("=" * 60)
                
                    # Wait for all geos to complete and collect results
                    completed_geos = []
                    failed_geos = []
                    for future in as_completed(geo_futures):
                        geo = geo_futures[future]
                        try:
                            geo_results = future.result(timeout=3600)  # 1 hour timeout per geo
                            all_geo_results.extend(geo_results)
                            completed_geos.append(geo)
                            success_count = sum(1 for r in geo_results if r.get('success'))
                            total_count = len(geo_results)
                            failed_count = total_count - success_count
                            logger.info("=" * 60)
                            logger.info(f"[BULK] [{geo}] ✓✓✓ GEO COMPLETED: {success_count}/{total_count} success, {failed_count} failed")
                            logger.info(f"[BULK] [{geo}] Functions processed: {len(geo_batches_list)}")
                            logger.info(f"[BULK] [{geo}] Results count: {len(geo_results)}")
                            logger.info(f"[BULK] Completed geos so far: {len(completed_geos)}/{len(geo_futures)}")
                            if failed_count > 0:
                                logger.warning(f"[BULK] [{geo}] ⚠️ Some failures detected: {failed_count} user(s) failed")
                            logger.info("=" * 60)
                        except Exception as e:
                            logger.error("=" * 60)
                            logger.error(f"[BULK] [{geo}] ✗✗✗ GEO EXCEPTION (Future Error): {e}")
                            logger.error(f"[BULK] [{geo}] Error type: {type(e).__name__}")
                            logger.error(f"[BULK] [{geo}] Traceback: {traceback.format_exc()}")
                            logger.error("=" * 60)
                            failed_geos.append(geo)
                            completed_geos.append(geo)  # Mark as completed even if failed
                            
                            # Add failed results for all users in this geo
                            if geo in batches_by_geo:
                                for func_num, batch_users in batches_by_geo[geo]:
                                    for u in batch_users:
                                        all_geo_results.append({
                                            'email': u['email'],
                                            'success': False,
                                            'error': f'Geo processing exception for {geo}: {str(e)}'
                                        })
                
                    logger.info("=" * 60)
                    logger.info(f"[BULK] ===== ALL GEOS COMPLETED PROCESSING =====")
                    logger.info(f"[BULK] Total geos processed: {len(completed_geos)}/{len(geo_futures)}")
                    logger.info(f"[BULK] Completed geos: {completed_geos}")
                    logger.info(f"[BULK] Total results collected: {len(all_geo_results)}")
                    logger.info("=" * 60)
            
            # Set job status to completed (outside ThreadPoolExecutor but inside app_context)
            # Use lock to ensure thread-safe access
            with jobs_lock:
                if job_id in active_jobs:
                    completed_count = active_jobs[job_id].get('completed', 0)
                    success_count = active_jobs[job_id].get('success', 0)
                    failed_count = active_jobs[job_id].get('failed', 0)
                    active_jobs[job_id]['status'] = 'completed'
                    logger.info(f"[BULK] ✅ Job {job_id} completed successfully. Processed {completed_count}/{len(users)} users. Success: {success_count}, Failed: {failed_count}")
                else:
                    logger.error(f"[BULK] ⚠️ Job {job_id} not found in active_jobs when trying to mark as completed!")
                    # Try to create it if it doesn't exist (shouldn't happen, but safety check)
                    # Since we don't have the actual counts, use defaults
                    active_jobs[job_id] = {
                        'total': len(users),
                        'completed': 0,
                        'success': 0,
                        'failed': len(users),
                        'results': [],
                        'status': 'completed'
                    }
                    logger.warning(f"[BULK] Created fallback job entry for {job_id} with default values")
        except Exception as bg_error:
            logger.error(f"[BULK] ❌ CRITICAL ERROR in background_process: {bg_error}")
            logger.error(f"[BULK] Traceback: {traceback.format_exc()}")
            # Use lock to ensure thread-safe access
            with jobs_lock:
                if job_id in active_jobs:
                    active_jobs[job_id]['status'] = 'failed'
                    active_jobs[job_id]['error'] = str(bg_error)
                    active_jobs[job_id]['completed'] = active_jobs[job_id].get('completed', 0)
                else:
                    logger.error(f"[BULK] ⚠️ Job {job_id} not found in active_jobs when trying to mark as failed!")

    threading.Thread(target=background_process, args=(app, job_id, users, access_key, secret_key, region)).start()

    return jsonify({'success': True, 'job_id': job_id, 'message': f'Started processing {len(users)} users'})'''

try:
    with open(TARGET_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    # Define markers for the block to replace
    start_marker = "@aws_manager.route('/api/aws/bulk-generate', methods=['POST'])"
    end_marker = "return jsonify({'success': True, 'job_id': job_id, 'message': f'Started processing {len(users)} users'})"

    start_idx = content.find(start_marker)
    end_idx = content.find(end_marker)

    if start_idx == -1 or end_idx == -1:
        print("Could not find markers!")
        print(f"Start found: {start_idx}")
        print(f"End found: {end_idx}")
        exit(1)

    # Include the end marker in the replacement (or rather, append it back if needed, but NEW_CONTENT includes it)
    # NEW_CONTENT ends with the return statement, so we should replace up to the end of that line.
    
    # Find the end of the line for end_marker
    end_line_end = content.find('\n', end_idx)
    if end_line_end == -1:
        end_line_end = len(content)

    new_file_content = content[:start_idx] + NEW_CONTENT + content[end_line_end:]

    with open(TARGET_FILE, 'w', encoding='utf-8') as f:
        f.write(new_file_content)

    print("Successfully replaced bulk_generate!")

except Exception as e:
    print(f"Error: {e}")
