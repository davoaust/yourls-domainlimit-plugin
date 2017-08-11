<?php
/*
Plugin Name: Domain Limiter
Plugin URI:  https://github.com/davoaust/yourls-domainlimit-plugin
Description: Only allow URLs from admin-specified domains and the option to exclude specific domains
Version: 1.1.3-qut.to
Author: davoaust
Author URI: https://github.com/davoaust
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

yourls_add_filter( 'shunt_add_new_link', 'domainlimit_link_filter' );

function domainlimit_link_filter( $original_return, $url, $keyword = '', $title = '' ) {
	if ( domainlimit_environment_check() != true || domainexclude_environment_check() != true ) {
		$err = array();
		$err['status'] = 'fail';
		$err['code'] = 'error:configuration';
		$err['message'] = 'Problem with Domain Limiter plugin configuration. Check PHP error log.';
		$err['errorCode'] = '500';
		return $err;
	}

	// If the user is exempt, don't even bother checking.
	global $domainlimit_exempt_users;
	if ( in_array( YOURLS_USER, $domainlimit_exempt_users ) ) {
		return $original_return;
	}

    $domainlimit_list = json_decode(yourls_get_option('domainlimit_list'), TRUE);
	$domain_whitelist = $domainlimit_list;

	$domainexclude_list = json_decode(yourls_get_option('domainexclude_list'), TRUE);
	$domain_blacklist = $domainexclude_list;

	// The plugin hook gives us the raw URL input by the user, but
	// it needs some cleanup before it's suitable for parse_url().
	$url = yourls_encodeURI( $url );
	$url = yourls_escape( yourls_sanitize_url( $url) );
	if ( !$url || $url == 'http://' || $url == 'https://' ) {
		$return['status']    = 'fail';
		$return['code']      = 'error:nourl';
		$return['message']   = yourls__( 'Missing or malformed URL' );
		$return['errorCode'] = '400';
		return yourls_apply_filter( 'add_new_link_fail_nourl', $return, $url, $keyword, $title );
	}

	$allowed = false;
	$requested_domain = parse_url($url, PHP_URL_HOST);

	// check against whitelisted domains & subdomains
	foreach ( $domain_whitelist as $domain_permitted ) {
		if ( domainlimit_is_subdomain( $requested_domain, $domain_permitted ) ) {
			$allowed = true;
			break;
		}
	}

	// check against blacklisted domains & subdomains
	foreach ( $domain_blacklist as $domain_excluded ) {
		if ( domainlimit_is_subdomain( $requested_domain, $domain_excluded ) ) {
			$allowed = false;
			break;
		}
	}

	if ( $allowed == true ) {
		return $original_return;
	}

	$return = array();
	$return['status'] = 'fail';
	$return['code'] = 'error:disallowedhost';
	$return['message'] = 'URL must be in "' . implode(', ', $domain_whitelist) . '", and cannot be in "' . implode(', ', $domain_blacklist) . '"';
	$return['errorCode'] = '400';
	return $return;
}

/*
 * Determine whether test_domain is controlled by $parent_domain
 */
function domainlimit_is_subdomain( $test_domain, $parent_domain ) {
	if ( $test_domain == $parent_domain ) {
		return true;
	}

	// Are we wildcard checking subdomains?
	if ( substr( $parent_domain, 0, 1) == '*' ) {
		// Remove the wildcard
		$parent_domain = str_replace("*", "", $parent_domain);

		// note that "notunbc.ca" is NOT a subdomain of "unbc.ca"
		// We CANNOT just compare the rightmost characters
		// unless we add a period in there first
		if ( substr( $parent_domain, 0, 1) != '.' ) {
			$parent_domain = '.' . $parent_domain;
		}

		$chklen = strlen($parent_domain);
		return ( $parent_domain == substr( $test_domain, 0-$chklen ) );
	} else {
		return false;
	}
}

// returns true if $domainlimit_list is defined
function domainlimit_environment_check() {
	if (yourls_get_option('domainlimit_list') !== false) {
		$domainlimit_list = json_decode(yourls_get_option('domainlimit_list'), TRUE);
	} else {
		yourls_add_option('domainlimit_list');
	}
	if ( !isset( $domainlimit_list ) ) {
		error_log('Missing definition of $domainlimit_list in database');
		return false;
	} else if ( isset( $domainlimit_list ) && !is_array( $domainlimit_list ) ) {
		// be friendly and allow non-array definitions
		$domain = $domainlimit_list;
		$domainlimit_list = array( $domain );
		return true;
	}
	return true;
}


// logs warning if $domainexclude_list is not defined
function domainexclude_environment_check() {
	if (yourls_get_option('domainexclude_list') !== false) {
		$domainexclude_list = json_decode(yourls_get_option('domainexclude_list'), TRUE);
	} else {
		yourls_add_option('domainexclude_list');
	}
	
	if ( !isset( $domainexclude_list ) ) {
		error_log('Missing definition of $domainexclude_list in user/config.php, using an empty list');
		$domainexclude_list = array();
	} else if ( isset( $domainexclude_list ) && !is_array( $domainexclude_list ) ) {
		// be friendly and allow non-array definitions
		$domain = $domainexclude_list;
		$domainexclude_list = array( $domain );
	}
	return true;
}


// Register your plugin admin page
yourls_add_action( 'plugins_loaded', 'domainlimit_init' );
function domainlimit_init() {
    yourls_register_plugin_page( 'domainlimit', 'Domain Limiter Settings', 'domainlimit_display_page' );
}

// The function that will draw the admin page
function domainlimit_display_page() {
    // Check if a form was submitted
	if( isset( $_POST['domainlimit_submit'] ) ) {
		domainlimit_config_update();
	}
	
    $domainlimit_list_option = yourls_get_option( 'domainlimit_list' );
	$domainexclude_list_option = yourls_get_option( 'domainexclude_list' );
	
    foreach (json_decode($domainlimit_list_option) as $domain) {
    	$domainlimit_list .= $domain.PHP_EOL;
    }
	foreach (json_decode($domainexclude_list_option) as $domain) {
    	$domainexclude_list .= $domain.PHP_EOL;
    }
	
	$disabled = false;
	$nonce = yourls_create_nonce( 'form_nonce' ) ;

	echo "<h3>Domain Limiter Settings</h3>";

	echo <<<HTML
	    <form method="post">
		<p>Please enter each URL on a new line</p>
		<input type="hidden" name="domainlimit_submit" value="1" />
		<input type="hidden" name="nonce" value="{$nonce}" />
		<label for = "domainlimit_list">Allowed domains:</label>
		<textarea name="domainlimit_list" id="domainlimit_list" style="width:100%;min-height:7em;">{$domainlimit_list}</textarea>
		<label for = "domainexclude_list">Excluded domains (even if matched by above):</label>
		<textarea name="domainexclude_list" id="domainexclude_list" style="width:100%;min-height:7em;">{$domainexclude_list}</textarea>
		<button type='submit'>Save</button>
HTML;
}

// Check and update
function domainlimit_config_update() {
	yourls_verify_nonce( 'form_nonce' ) ;
		
	if( isset( $_POST['domainlimit_list'] ) )
			domainlimit_config_update_option();

	if( isset( $_POST['domainexclude_list'] ) )
			domainexclude_config_update_option();
}

// Update option in database
function domainlimit_config_update_option() {
    $list_array = explode(PHP_EOL, $_POST['domainlimit_list']);
    foreach ($list_array as $domain) {
    	if(trim($domain)!="")
    	$list[] = filter_var(trim($domain), FILTER_SANITIZE_URL);
    }

    if($list) {

        $jsonlist = json_encode( $list );

        if (yourls_get_option('domainlimit_list') !== false) {
            yourls_update_option('domainlimit_list', $jsonlist);
        } else {
            yourls_add_option('domainlimit_list', $jsonlist);
        }
    }
}

// Update exclude in database
function domainexclude_config_update_option() {
    $list_array = explode(PHP_EOL, $_POST['domainexclude_list']);
    foreach ($list_array as $domain) {
    	if(trim($domain)!="")
    	$list[] = filter_var(trim($domain), FILTER_SANITIZE_URL);
    }

    if($list) {

        $jsonlist = json_encode( $list );

        if (yourls_get_option('domainexclude_list') !== false) {
            yourls_update_option('domainexclude_list', $jsonlist);
        } else {
            yourls_add_option('domainexclude_list', $jsonlist);
        }
    }
}
