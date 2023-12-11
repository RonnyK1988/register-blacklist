<?php

// If uninstall not called from WordPress, then exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

$delete_db_tables = get_option( 'reg_black_delete_db_tables', 0 );

if ( $delete_db_tables ) {

    $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}reg_black_domains" );
    $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}reg_black_emails" );
    $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}reg_black_attempts" );
    $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}reg_black_options" );

}

// Delete the option for deleting tables on plugin deactivation
delete_option( 'reg_black_delete_db_tables' );

$reg_black_file = plugin_dir_path( __FILE__ ) . 'register-blacklist.php';

if ( file_exists( $reg_black_file ) ) {
    unlink( $reg_black_file );
}

?>