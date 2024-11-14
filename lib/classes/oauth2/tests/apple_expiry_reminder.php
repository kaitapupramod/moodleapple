<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace core\oauth2\tests;

/**
 * External core oauth2 API tests.
 *
 * @package    core
 * @copyright  2017 Damyon Wiese
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 *
 * @covers \core\oauth2\apple_expiry_reminder
 */
class apple_expiry_reminder extends \advanced_testcase {

    /**
     * @var object $appleissuer New appleissuer created to test the expiry reminder email.
     */
    protected $appleissuer = null;
    /**
     * Called before every test.
     */
    public function setUp(): void {
        parent::setUp();
        $classname = 'core\\oauth2\\service\\apple';
        if (class_exists($classname)) {
            $issuer = $classname::init();
            $issuer->create();
            $this->appleissuer = $issuer;

        }
    }
    /**
     * Test expiry reminder email via the send apple expiry reminder email method.
     *
     * @covers  \core\oauth2\apple_expiry_reminder::send_expiry_reminder_email
     */
    public function test_send_apple_expiry_reminder_email(): void {

        $this->resetAfterTest();
        $this->setAdminUser();
        
        // Set past expiry date.
        $pastdate = strtotime('-1 week');

        $secretkey = $this->generate_secretkey($pastdate);

        // Set client id to issuer object.
        $this->appleissuer->set('clientid', 'apple1');

        // Set client secret to issuer object.
        $this->appleissuer->set('clientsecret', $secretkey);

        // Check service expiry email sent or not.
        $ismailsent = (new \core\oauth2\apple_expiry_reminder)->send_expiry_reminder_email($this->appleissuer);

        // Confirm the reminder email sent.
        $this->assertEquals(true, $ismailsent);


        // Set future expiry date.
        $futuredate = strtotime('+1 week');

        $secretkey = $this->generate_secretkey($futuredate);
        // Set client id to issuer object.
        $this->appleissuer->set('clientid', 'apple1');

        // Set client secret to issuer object.
        $this->appleissuer->set('clientsecret', $secretkey);

        // Check service expiry email sent or not.
        $ismailsent = (new \core\oauth2\apple_expiry_reminder)->send_expiry_reminder_email($this->appleissuer);

        // Confirm the reminder email is not sent.
        $this->assertEquals(false, $ismailsent);

    }

    /**
     * Generate secret key.
     *
     * @param int $date expiry date to generate the key.
     * @return string
     */
    protected function generate_secretkey($date) {
        global $DB;

        // Set the sample data to generate the secret key.
        $tokeninfo = [];
        $tokeninfo['iat'] = 'apple1';
        $tokeninfo['exp'] = $date;
        $tokeninfo['aud'] = 'https://appleid.apple.com';
        $tokeninfo['sub'] = 'apple1';

        // Generate sample secret key
        $secretkey = $this->create_json_encoded_token($tokeninfo);
        return $secretkey;
    }

    /**
     * Create json encoded token.
     *
     * @param   array $data The key information to process and create the secretkey.
     * @return  string
     */
    protected function create_json_encoded_token($data = []) {
        $secretkey = \Firebase\JWT\JWT::urlsafeB64Encode(\Firebase\JWT\JWT::jsonEncode($data));
        $parta = 'appletesta.';
        $partb = '.appletestb';
        return $parta.$secretkey.$partb;
    }
}
