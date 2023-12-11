<?php

/*
    * Plugin Name:          Register Blacklist
    * Description:          Prevents registration with specified email domains and email addresses.
    * Version:              1.20
    * Requires at least:    6.0
    * Requires PHP:         7.2
    * Author:               Ronny Kreuzberg
    * Author URI:           https://www.ronny-kreuzberg.de
    * License:              GPL v2 or later
    * License URI:          https://www.gnu.org/licenses/gpl-2.0.html
    * Text Domain:          register-blacklist
*/

if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

function reg_black_activate() {

    global $wpdb;

    $table_name_domains = $wpdb->prefix . 'reg_black_domains';
    $table_name_emails = $wpdb->prefix . 'reg_black_emails';
    $table_name_attempts = $wpdb->prefix . 'reg_black_attempts';
    $table_name_options = $wpdb->prefix . 'reg_black_options';

    $charset_collate = $wpdb->get_charset_collate();

    $sql_domains = "CREATE TABLE IF NOT EXISTS $table_name_domains (

        id mediumint(9) NOT NULL AUTO_INCREMENT,
        domain varchar(255) NOT NULL,
        PRIMARY KEY  (id)

    ) $charset_collate;";

    $sql_emails = "CREATE TABLE IF NOT EXISTS $table_name_emails (

        id mediumint(9) NOT NULL AUTO_INCREMENT,
        email varchar(255) NOT NULL,
        PRIMARY KEY  (id)

    ) $charset_collate;";

    $sql_attempts = "CREATE TABLE IF NOT EXISTS $table_name_attempts (

        id mediumint(9) NOT NULL AUTO_INCREMENT,
        domain varchar(255) NOT NULL,
        email varchar(255) NOT NULL,
        blocked_attempts_count int(11) NOT NULL DEFAULT 0,
        last_login_attempt datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
        PRIMARY KEY  (id)

    ) $charset_collate;";

    $sql_options = "CREATE TABLE IF NOT EXISTS $table_name_options (

        id mediumint(9) NOT NULL AUTO_INCREMENT,
        delete_on_deactivation tinyint(1) NOT NULL DEFAULT 0,
        PRIMARY KEY  (id)

    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );

    dbDelta( $sql_domains );
    dbDelta( $sql_emails );
    dbDelta( $sql_attempts );
    dbDelta( $sql_options );

    // An array of domains to add to the domain table upon activation

    $initial_domains = array(
        '1secmail.com',
        '1secmail.org',
        'captchas.biz',
        'circlebpo.com',
        'decaptcha.biz',
        'gemination.hair',
        'gemination.hair',
        'getadsnow.org',
        'hotpublisher.org',
        'mailbab.com',
        'mailkv.com',
        'maillsk.com',
        'maillv.com',
        'oonmail.com',
        'voiceoftruth.info',
        'znemail.com'
    );

    // Get the existing domains from the database

    $existing_domains = $wpdb->get_col("SELECT domain FROM $table_name_domains");

    // Add the domains if they don't already exist
    
    foreach ($initial_domains as $domain) {

        if ( ! in_array($domain, $existing_domains ) ) {

            $wpdb->insert( $table_name_domains, array( 'domain' => $domain ) );
        }
    }

    add_option( 'reg_black_delete_db_tables', 0 );

}

register_activation_hook( __FILE__, 'reg_black_activate' );

// Function to block registration with specified email domains

function reg_black_registration_check( $errors, $sanitized_user_login, $user_email ) {

    global $wpdb;

    $blocked_domains = $wpdb->get_col("SELECT domain FROM {$wpdb->prefix}reg_black_domains");

    $blocked_emails = $wpdb->get_col("SELECT email FROM {$wpdb->prefix}reg_black_emails");

    list($user, $domain) = explode('@', $user_email);

    if ( in_array( $domain, $blocked_domains ) || in_array( $user_email, $blocked_emails ) ) {

        $errors->add( 'email_blocked', 'Registration with this email or domain is not allowed.' );

        // Update statistics for blocked attempts

        $wpdb->query($wpdb->prepare(

            "INSERT INTO {$wpdb->prefix}reg_black_attempts (domain, email, blocked_attempts_count, last_login_attempt)
            VALUES (%s, %s, 1, NOW())
            ON DUPLICATE KEY UPDATE blocked_attempts_count = blocked_attempts_count + 1, last_login_attempt = NOW()",
            $domain, $user_email

        ));

    }

    return $errors;

}

add_filter( 'registration_errors', 'reg_black_registration_check', 10, 3 );

// Add settings link to the plugin page

function reg_black_settings_link( $links ) {

    $settings_link = '<a href="options-general.php?page=reg-black-settings">' _e( "Settings" ) '</a>';

    array_unshift( $links, $settings_link );

    return $links;

}

$plugin_basename = plugin_basename( __FILE__ );

add_filter( 'plugin_action_links_$plugin_basename', 'reg_black_settings_link' );

// Create settings pages

function reg_black_settings_page() {

    if ( ! current_user_can( 'manage_options' ) ) {

        return;

    }

    global $wpdb;
    
    $delete_db_tables = get_option( 'reg_black_delete_db_tables', false );

    $reg_black_nonce = wp_create_nonce( "reg_black_nonce" ); ?>

	<input type="hidden" id="reg-black-nonce" name="reg-black-nonce" value="<?php echo esc_attr( $reg_black_nonce ); ?>">


    <?php if ( isset ($_POST['reg_black_domains'] ) ) {

        $blocked_domains = sanitize_text_field( $_POST['reg_black_domains'] );

        $blocked_domains = explode( ',', $blocked_domains );

        $blocked_domains = array_map( 'trim', $blocked_domains );

        foreach ($blocked_domains as $domain) {

            $wpdb->insert(

                "{$wpdb->prefix}reg_black_domains",

                array('domain' => $domain),

                array('%s')

            );

        }

    }

    if ( isset( $_POST['reg_black_emails'] ) ) {

        $blocked_emails = sanitize_text_field( $_POST['reg_black_emails'] );
        $blocked_emails = explode(',', $blocked_emails);
        $blocked_emails = array_map('trim', $blocked_emails);

        foreach ( $blocked_emails as $email ) {

            $wpdb->insert(

                "{$wpdb->prefix}reg_black_emails",
                array('email' => $email),
                array('%s')

            );
        }
    }

    if ( isset( $_POST['reg_black_delete_db_tables'] ) ) {

        $delete_db_tables = isset( $_POST['reg_black_delete_db_tables'] ) ? 1 : 0;

        // Update the option for deleting tables on plugin deactivation

        update_option( 'reg_black_delete_db_tables', $delete_db_tables );
    }

    $delete_db_tables = get_option( 'reg_black_delete_db_tables', 0 );

    $blocked_domains = $wpdb->get_col( "SELECT domain FROM {$wpdb->prefix}reg_black_domains" );
    $blocked_emails = $wpdb->get_col( "SELECT email FROM {$wpdb->prefix}reg_black_emails" );

    sort( $blocked_domains );
    sort( $blocked_emails );

    ?>

    <div class="wrap">

        <h2><?php _e( 'Register Blacklist Settings', 'register-blacklist' ); ?></h2>

        <h2 class="nav-tab-wrapper">

            <a class="nav-tab" href="#tab-domains"><?php _e( 'Domains', 'register-blacklist' ); ?></a>

            <a class="nav-tab" href="#tab-emails"><?php _e( 'Emails', 'register-blacklist' ); ?></a>

            <a class="nav-tab" href="#tab-statistics"><?php _e( 'Blocked Attempts', 'register-blacklist' ); ?></a>

            <a class="nav-tab" href="#tab-settings"><?php _e( 'Settings', 'register-blacklist' ); ?></a>

        </h2>

        <div id="tab-domains">

            <h3><?php _e( 'Blocked Domains', 'register-blacklist' ); ?></h3>

            <form method="post" action="">

                <label for="reg_black_domains"><?php _e( 'Blocked Domains (comma-separated):', 'register-blacklist' ); ?></label>

                <input type="text" id="reg_black_domains" name="reg_black_domains" placeholder="<?php _e( 'Enter a domain', 'register-blacklist' ); ?>">

                <input type="submit" class="button-primary" value="<?php _e( 'Add Domain', 'register-blacklist' ); ?>">

            </form>

            <ul>

                <?php foreach ( $blocked_domains as $domain ) : ?>

                    <li>

                        <?php echo esc_html( $domain ); ?>

                        <a class="delete-link" data-type="domain" data-value="<?php echo esc_attr( $domain ); ?>" href="#"><?php _e( 'Delete', 'register-blacklist' ); ?></a>

                    </li>

                <?php endforeach; ?>

            </ul>

        </div>

        <div id="tab-emails">

            <h3><?php _e( 'Blocked Email Addresses', 'register-blacklist' ); ?></h3>

            <form method="post">

                <label for="reg_black_emails"><?php _e( 'Blocked Email Addresses (comma-separated):', 'register-blacklist' ); ?></label>

                <input type="text" id="reg_black_emails" name="reg_black_emails" placeholder="<?php _e( 'Enter an email address', 'register-blacklist' ); ?>">

                <input type="submit" class="button-primary" value="<?php _e( 'Add Email', 'register-blacklist' ); ?>">

            </form>

            <ul>

                <?php foreach ( $blocked_emails as $email ) : ?>

                    <li>

                        <?php echo esc_html( $email ); ?>

                        <a class="delete-link" data-type="email" data-value="<?php echo esc_attr( $email ) ; ?>" href="#"><?php _e( 'Delete', 'register-blacklist' ); ?></a>

                    </li>

                <?php endforeach; ?>

            </ul>

        </div>

        <div id="tab-statistics">

            <h3><?php _e( 'Blocked Register Attempts', 'register-blacklist' ); ?></h3>

            <?php

            $blocked_domains = $wpdb->get_results(
                
                "SELECT domain, SUM(blocked_attempts_count) 
                AS blocked_count, MAX(last_login_attempt) 
                AS last_attempt 
                FROM {$wpdb->prefix}reg_black_attempts 
                WHERE domain IS NOT NULL GROUP BY domain"
            );
            
            $blocked_emails = $wpdb->get_results(

                "SELECT domain, email, SUM(blocked_attempts_count) 
                AS blocked_count, MAX(last_login_attempt) 
                AS last_attempt 
                FROM {$wpdb->prefix}reg_black_attempts 
                WHERE email IS NOT NULL GROUP BY email"

            );

            if ( ! empty( $blocked_domains) ) {

                echo '<h4>' . __( 'Blocked Domains', 'register-blacklist' ) . '</h4>';

                echo '<table class="wp-list-table widefat fixed striped">';

                echo '<thead><tr><th>' . __( 'Domain', 'register-blacklist' ) . '</th><th>' . __( 'Blocked Attempts', 'register-blacklist' ) . '</th><th>' . __( 'Last Login Attempt', 'register-blacklist' ) . '</th></tr></thead>';

                echo '<tbody>';

                foreach ( $blocked_domains as $domain ) {

                    echo '<tr>';

                    echo '<td>' . esc_html( $domain->domain ) . '</td>';

                    echo '<td>' . intval( $domain->blocked_count ) . '</td>';

                    echo '<td>' . esc_html( $domain->last_attempt ) . '</td>';

                    echo '</tr>';

                }

                echo '</tbody>';

                echo '</table>';

            } else {

                echo '<p>' . __(' No blocked domains recorded.', 'register-blacklist' ) . '</p>';

            }

            if ( ! empty( $blocked_emails ) ) {

                echo '<h4>' . __( 'Blocked Email Addresses', 'register-blacklist' ) . '</h4>';

                echo '<table class="wp-list-table widefat fixed striped">';

                echo '<thead><tr><th>' . __( 'Email', 'register-blacklist' ) . '</th><th>' . __( 'Blocked Attempts', 'register-blacklist' ) . '</th><th>' . __( 'Last Login Attempt', 'register-blacklist' ) . '</th></tr></thead>';

                echo '<tbody>';

                foreach ( $blocked_emails as $email ) {

                    echo '<tr>';

                    echo '<td>' . esc_html( $email->email ) . '</td>';

                    echo '<td>' . intval( $email->blocked_count ) . '</td>';

                    echo '<td>' . esc_html( $email->last_attempt ) . '</td>';

                    echo '</tr>';

                }

                echo '</tbody>';

                echo '</table>';

            } else {

                echo '<p>' . __( 'No blocked email addresses recorded.', 'register-blacklist' ) . '</p>';

            }

            ?>

        </div>

        <div id="tab-settings">

            <h3><?php _e( 'Plugin Settings', 'register-blacklist' ); ?></h3>

            <form method="post">

                <label for="reg_black_delete_db_tables"><?php _e( 'Delete all files and DB Tables on Plugin Deactivation:', 'register-blacklist' ); ?></label>

                <input type="checkbox" id="reg_black_delete_db_tables" name="reg_black_delete_db_tables" <?php echo $delete_db_tables ? 'checked="checked"' : ''; ?>>

                <input type="submit" class="button-primary" name="reg_black_settings_submit" value="<?php _e( 'Save Settings', 'register-blacklist' ); ?>">

            </form>

        </div>

    </div>

    <script defer>

        document.addEventListener('DOMContentLoaded', function () {

            // Set the "Domains" tab as active initially

            document.querySelector('.nav-tab[href="#tab-domains"]').classList.add('nav-tab-active');

            // Add click event listeners to toggle tab visibility

            const tabs = document.querySelectorAll('.nav-tab');

            tabs.forEach(tab => {

                tab.addEventListener('click', (event) => {

                    event.preventDefault();

                    const targetId = event.target.getAttribute('href').substr(1);

                    document.querySelectorAll('.nav-tab').forEach(navTab => navTab.classList.remove('nav-tab-active'));

                    event.target.classList.add('nav-tab-active');

                    document.querySelectorAll('#tab-domains, #tab-emails, #tab-settings, #tab-statistics').forEach(tabContent => {

                        if (tabContent.id === targetId) {

                            tabContent.style.display = 'block';

                        } else {

                            tabContent.style.display = 'none';

                        }

                    });

                });

            });

        });

        // Add a click event listener to the delete links

        const deleteLinks = document.querySelectorAll(".delete-link");

        deleteLinks.forEach(link => {

            link.addEventListener("click", function (event) {

                event.preventDefault();

                const type = this.getAttribute("data-type");

                const value = this.getAttribute("data-value");

                if (confirm("Are you sure you want to delete this " + type + "?")) {

                    // Generate and use a nonce

                    const nonce = document.querySelector("#reg-black-nonce").value;

                    // Send an AJAX request to delete the domain or email

                    const data = new URLSearchParams({

                        action: "reg_black_delete_entry",

                        type,

                        value,

                        _wpnonce: nonce,

                    });

                    fetch(ajaxurl, {

                        method: "POST",

                        headers: {

                            "Content-Type": "application/x-www-form-urlencoded",

                        },

                        body: data,
                    })

                    .then(response => response.json())

                    .then(result => {

                        if (result.success) {

                            // Reload the page after deletion

                            location.reload();

                        } else {

                            alert("Failed to delete " + type + ". Please try again.");

                        }

                    })

                    .catch(error => {

                        alert("An error occurred while deleting " + type + ".");

                    });

                }

            });
        
        });

    </script>

    <?php
}

function reg_black_register_settings_page() {

    add_submenu_page(

        'options-general.php',
        'Register Blacklist Settings',
        'Register Blacklist',
        'manage_options',
        'reg-black-settings',
        'reg_black_settings_page'

    );

}

add_action( 'admin_menu', 'reg_black_register_settings_page' );

// function to delete domain or email from the blacklist

function reg_black_delete_entry() {

    if ( ! isset( $_POST["_wpnonce"] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST["_wpnonce"] ) ), "reg_black_nonce") ) {

        wp_send_json_error( ["message" => "Nonce verification failed."] );

    }

    if ( ! current_user_can( "manage_options") ) {

        wp_send_json_error( ["message" => "Permission denied."] );

    }

    if (isset( $_POST["type"] ) && isset( $_POST["value"] ) ) {

        global $wpdb;

        $type = sanitize_text_field( $_POST["type"] );

        $value = sanitize_text_field( $_POST["value"] );

        if ( $type === "domain" ) {

            $table_name = $wpdb->prefix . "reg_black_domains";

            $column_name = "domain";

        } elseif ( $type === "email" ) {

            $table_name = $wpdb->prefix . "reg_black_emails";

            $column_name = "email";

        } else {

            wp_send_json_error( ["message" => "Invalid type."] );

        }

        // Attempt to delete the entry from the appropriate table

        $result = $wpdb->delete( $table_name, [$column_name => $value] );

        if ( $result === false ) {

            wp_send_json_error( ["message" => "Failed to delete the " . $type . "."] );

        }

        wp_send_json_success( ["message" => $type . " deleted successfully."] );

    } else {

        wp_send_json_error( ["message" => "Missing data."] );

    }

}

add_action( "wp_ajax_reg_black_delete_entry", "reg_black_delete_entry" );

add_action( "wp_ajax_nopriv_reg_black_delete_entry", "reg_black_delete_entry" );

// CSS Styles

function reg_black_enqueue_admin_styles() {

    wp_enqueue_style( 'reg-black-admin-styles', plugins_url( 'css/reg-black-styles.css', __FILE__ ));

}

add_action( 'admin_enqueue_scripts', 'reg_black_enqueue_admin_styles' );

?>