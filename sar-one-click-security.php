<?php
/*
Plugin Name: SAR One Click Security
Plugin URI: http://www.samuelaguilera.com/archivo/protege-wordpress-facilmente.xhtml
Description: Adds some extra security to your WordPress with only one click.
Author: Samuel Aguilera
Version: 1.2.2
Author URI: http://www.samuelaguilera.com
Text Domain: sar-one-click-security
License: GPL3
*/

/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as published by
the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

if ( !defined( 'ABSPATH' ) ) { exit; } // Not needed in this case, but maybe in the future...

// Current plugin version
define('SAR_OCS_VER', '1.2.2');

function sar_ocs_init() {

	global $is_apache;

	// Load language file first
	load_plugin_textdomain( 'sar-one-click-security', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );

	if ( ! $is_apache ) {

			function sar_apache_not_found() {
				$message = sprintf( wp_kses_allowed_html( __( '%sSAR One Click Security only supports Apache2 servers%s. Your server is not supported, you should deactivate and delete this plugin.', 'sar-one-click-security' ) ), '<strong>', '</strong>' );
			    ?>
			    <div class="error">
			        <p><?php echo $message; ?></p>
			    </div>
			    <?php
			}
			add_action( 'admin_notices', 'sar_apache_not_found' );

			return;

	}

	// Needs upgrade?
	$current_ver = get_option('sar_ocs_ver');

	if ( false === $current_ver /* For older releases where SAR_OCS_VER was not introduced yet */ || version_compare( $current_ver, SAR_OCS_VER, '<' ) || '111' == $current_ver ) {

		// Upgrade rules
		sar_remove_security_rules();
		sar_add_security_rules();

		// Update current ver to DB
		update_option( 'sar_ocs_ver', SAR_OCS_VER );

	}	

}

add_action( 'admin_init', 'sar_ocs_init' );


function sar_ocs_activation(){

	global $is_apache;

	if ( $is_apache ) {
		// Adds current ver to DB
		add_option( 'sar_ocs_ver', SAR_OCS_VER );

		// Install security rules
		sar_add_security_rules();
	}

}

function sar_ocs_deactivation(){

	// Remove security rules
	sar_remove_security_rules();

	// Remove options stored
	delete_option( 'sar_ocs_ver' );
}

register_activation_hook( __FILE__, 'sar_ocs_activation' );
register_deactivation_hook( __FILE__, 'sar_ocs_deactivation' );


function sar_add_security_rules(){

		$is_apache_24 = strpos( $_SERVER["SERVER_SOFTWARE"],'Apache/2.4' ) !== false ? true : false;
		// Path to .htaccess
		$htaccess = get_home_path() . ".htaccess";
		$wp_content_htaccess = WP_CONTENT_DIR . '/.htaccess';

		// WordPress domain
		$wp_url = get_bloginfo( 'wpurl' );
		$wp_url = parse_url( $wp_url );
		$wp_domain = preg_replace('#^www\.(.+\.)#i', '$1', $wp_url['host']); // only removes www from beginning, allowing domains that contains www on it
		$wp_domain = explode(".",$wp_domain);

		// Support for multisite subdomains
		$domain_parts = count($wp_domain);

		// assumming domain is supported by default
		$wp_domain_not_supported = false;

		if ( $domain_parts === 2 ) {
			$wp_domain_exploded = $wp_domain[0] . '\.' . $wp_domain[1];
		} elseif ( $domain_parts === 3 ) {
			$wp_domain_exploded = $wp_domain[0] . '\.' . $wp_domain[1] . '\.' . $wp_domain[2];
		} else {
			$wp_domain_not_supported = true; // for IP based URLs
		}

		// Security rules	 
		$sec_rules = array();
		$sec_rules[] = "# Any decent hosting should have this set, but many don't have";
		$sec_rules[] = 'ServerSignature Off';
		$sec_rules[] = '<IfModule mod_autoindex.c>';
		$sec_rules[] = 'IndexIgnore *'; // Options -Indexes maybe is better, but some hostings doesn't allow the use of Options directives from .htaccess
		$sec_rules[] = '</IfModule>';

		$sec_rules[] = '# Block access to sensitive files';
		// Use Apache 2.4 syntax if $_SERVER["SERVER_SOFTWARE"] string contains Apache/2.4 or the constant is added to wp-config.php
		if ( $is_apache_24 || defined( 'SAR_APACHE24_SYNTAX' ) ) {
		$sec_rules[] = '<Files .htaccess>';
		$sec_rules[] = 'Require all denied';
		$sec_rules[] = '</Files>';
		$sec_rules[] = '<FilesMatch "^(license\.txt|readme\.html|wp-config\.php|wp-config-sample\.php|install\.php)$">';
		$sec_rules[] = 'Require all denied';
		$sec_rules[] = '</FilesMatch>';
		} else {
		$sec_rules[] = '<Files .htaccess>';
		$sec_rules[] = 'order allow,deny';
		$sec_rules[] = 'deny from all';
		$sec_rules[] = '</Files>';
		$sec_rules[] = '<FilesMatch "^(license\.txt|readme\.html|wp-config\.php|wp-config-sample\.php|install\.php)$">';
		$sec_rules[] = 'order allow,deny';
		$sec_rules[] = 'deny from all';
		$sec_rules[] = '</FilesMatch>';
		}

		$sec_rules[] = '# Stops dummy bots trying to register in WordPress sites that have registration disabled';
		$sec_rules[] = '<IfModule mod_rewrite.c>';
		$sec_rules[] = 'RewriteEngine On';
		$sec_rules[] = 'RewriteCond %{QUERY_STRING} ^action=register$ [NC,OR]';
		$sec_rules[] = 'RewriteCond %{HTTP_REFERER} ^.*registration=disabled$ [NC]';
		$sec_rules[] = 'RewriteRule (.*) - [F]';
		$sec_rules[] = '</IfModule>';

		if ( !defined( 'SAR_ALLOW_TIMTHUMB' ) ) {
			$sec_rules[] = '# Block requests looking for timthumb.php';	
			$sec_rules[] = '<IfModule mod_rewrite.c>';
			$sec_rules[] = 'RewriteEngine On';
			$sec_rules[] = 'RewriteRule ^(.*)/?timthumb\.php$ - [F]';
			$sec_rules[] = '</IfModule>';
		}

		$sec_rules[] = '# Block TRACE and TRACK request methods'; // TRACK is not availabe in Apache (without plugins) is a IIS method, but bots will try it anyway.
		$sec_rules[] = '<IfModule mod_rewrite.c>';
		$sec_rules[] = 'RewriteEngine On';
	    $sec_rules[] = 'RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)$';
	    $sec_rules[] = 'RewriteRule (.*) - [F]';
		$sec_rules[] = '</IfModule>';

		if (!$wp_domain_not_supported) { // We don't want to add this if the domain is not supported...
			$sec_rules[] = '# Blocks direct posting to wp-comments-post.php/wp-login.php and black User Agent';	
			$sec_rules[] = '<IfModule mod_rewrite.c>';
			$sec_rules[] = 'RewriteEngine On';
			$sec_rules[] = 'RewriteCond %{REQUEST_METHOD} ^(PUT|POST)$ [NC]';
			$sec_rules[] = 'RewriteCond %{REQUEST_URI} ^.(wp-comments-post|wp-login)\.php$ [NC]';
			$sec_rules[] = 'RewriteCond %{HTTP_REFERER} !^.*'.$wp_domain_exploded.'.*$ [OR]';
			$sec_rules[] = 'RewriteCond %{HTTP_USER_AGENT} ^$';
			$sec_rules[] = 'RewriteRule (.*) - [F]';
			$sec_rules[] = '</IfModule>';

		}

		// This may look like duplicated based on the above rule but it's not.
		$sec_rules[] = '# Block any query string trying to get a copy of wp-config.php file and gf_page=upload (deprecated on May 2015, update your copy of GF!).';
		$sec_rules[] = '<IfModule mod_rewrite.c>';
		$sec_rules[] = 'RewriteEngine On';
	    $sec_rules[] = 'RewriteCond %{QUERY_STRING} ^.*=(.*wp-config\.php)|gf_page=upload$ [NC]';
	    $sec_rules[] = 'RewriteRule (.*) - [F]';
		$sec_rules[] = '</IfModule>';

		// Block WPscan when using default user-agent
		$sec_rules[] = '# Block WPscan by user-agent';
		$sec_rules[] = '<IfModule mod_rewrite.c>';
		$sec_rules[] = 'RewriteEngine On';
	    $sec_rules[] = 'RewriteCond %{HTTP_USER_AGENT} WPScan';
	    $sec_rules[] = 'RewriteRule (.*) http://127.0.0.1 [L,R=301]';
		$sec_rules[] = '</IfModule>';

		// Insert rules to existing .htaccess or create new file if no .htaccess is present
		insert_with_markers($htaccess, "SAR One Click Security", $sec_rules);

		// Create .htacces for blocking direct access to PHP files in wp-content/ only if file .htaccess does not exists
		$wpc_htaccess_exists = file_exists ( $wp_content_htaccess );

		$wp_content_sec_rules = array();
		if ( $is_apache_24 || defined( 'SAR_APACHE24_SYNTAX' ) ) {
			$wp_content_sec_rules[] = '<FilesMatch "\.(php|php3|php5|php4|phtml)$">';
			$wp_content_sec_rules[] = 'Require all denied';
			$wp_content_sec_rules[] = '</FilesMatch>';
		} else {
			$wp_content_sec_rules[] = '<FilesMatch "\.(php|php3|php5|php4|phtml)$">';
			$wp_content_sec_rules[] = 'order allow,deny';
			$wp_content_sec_rules[] = 'deny from all';
			$wp_content_sec_rules[] = '</FilesMatch>';
		}			

		// Block access to .txt files under any plugin/theme directory to prevent scans for installed plugins/themes
		$wp_content_sec_rules[] = '<IfModule mod_rewrite.c>';
		$wp_content_sec_rules[] = 'RewriteEngine On';
		$wp_content_sec_rules[] = 'RewriteRule ^(themes|plugins)/(.*)/(.*)\.txt$ - [F]';
		$wp_content_sec_rules[] = '</IfModule>';

		if ( defined( 'SAR_ALLOW_TIMTHUMB' ) ) {
			$wp_content_sec_rules[] = '# Allow requests looking for TimThumb';	
			$wp_content_sec_rules[] = '<FilesMatch "^(timthumb|thumb)\.php$">';
			if ( $is_apache_24 || defined( 'SAR_APACHE24_SYNTAX' ) ) {
				$wp_content_sec_rules[] = 'Require all granted';
			} else {
				$wp_content_sec_rules[] = 'Order Allow,Deny';
				$wp_content_sec_rules[] = 'Allow from all';
			}			
			$wp_content_sec_rules[] = '</FilesMatch>';
		}

		// Stores an option to be sure that we delete (in the future) a file that we have created
		if ( ! $wpc_htaccess_exists ) { add_option( 'sar_ocs_wpc_htaccess', 'yes' ); } 

		// Insert rules to existing .htaccess or create new file if no .htaccess is present
		insert_with_markers( $wp_content_htaccess, "SAR One Click Security", $wp_content_sec_rules );		

}


function sar_remove_security_rules(){

	global $is_apache;

	if ( $is_apache ) {

		// Path to .htaccess
		$htaccess = get_home_path() . ".htaccess";
		$wp_content_htaccess = WP_CONTENT_DIR . '/.htaccess';

		$wp_content_htaccess_owned = get_option( 'sar_ocs_wpc_htaccess' );
		
		// Empty rules 
		$empty_sec_rules = array();
		
		// Remove rules. Markers will remain, but are only comments. TODO: Maybe create a new function to remove markers too. 
		insert_with_markers($htaccess, "SAR One Click Security", $empty_sec_rules);

		if ( $wp_content_htaccess_owned === 'yes' ) {

			// Remove .htacces from wp-content that we have created
			unlink( $wp_content_htaccess );
			delete_option('sar_ocs_wpc_htaccess');

		} else { // If the file was there before the plugin

			// Remove rules. Markers will remain, but are only comments. TODO: Maybe create a new function to remove markers too. 
			insert_with_markers( $wp_content_htaccess, "SAR One Click Security", $empty_sec_rules );

		}

	}

}

// Removes version information from being disclosed in page and syndication headers
function sar_remove_wp_version( $gen, $type ){

	switch ( $type ) {
		case 'html':
			$gen = '<meta name="generator" content="WordPress">';
			break;
		case 'xhtml':
			$gen = '<meta name="generator" content="WordPress" />';
			break;
		case 'atom':
			$gen = '<generator uri="https://wordpress.org/">WordPress</generator>';
			break;
		case 'rss2':
			$gen = '<generator>https://wordpress.org/</generator>';
			break;
		case 'rdf':
			$gen = '<admin:generatorAgent rdf:resource="https://wordpress.org/" />';
			break;
		case 'comment':
			$gen = '<!-- generator="WordPress" -->';
			break;
		// We don't need to remove the generator from exported files
	}

	return $gen;
}

add_filter( 'get_the_generator', 'sar_remove_wp_version', 10, 2 );
