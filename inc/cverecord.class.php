<?php

class PluginNvdCverecord {

    private const SEVERITIES = array(
        'CRITICAL'  => 9.0,
        'HIGH'      => 7.0,
        'MEDIUM'    => 4.0,
        'LOW'       => 0.1,
        'NONE'      => 0.0
    );

    private const baseCveUrl = "https://nvd.nist.gov/vuln/detail/";

    /**
     * Returns a string containing the severitu for the given score
     * 
     * @since 1.0.0
     * 
     * @param float $score  CVSS vulnerability score [0.0 - 10.0]
     * 
     * @return string       Severity for the given score [ NONE | LOW | MEDIUM | HIGH | CRITICAL ]
     */
    public static function getCvssScoreSeverity($score) {

        foreach(self::SEVERITIES as $severity => $limit) {
            
            if ($score >= $limit) {
                return $severity;
            }
        }
    } 

    /**
     * Retrieve url to CVE reccord on NVD database
     * 
     * @since 1.0.0
     * 
     * @param string $CveID     MITRE CVE vulnerability identifier
     * 
     * @return string 
     */
    public static function getCveNvdUrl($CveID) {

        return self::baseCveUrl . $CveID;
    }

    /**
     * Get vulnerability description for given language
     * 
     * @since 1.0.0
     * 
     * @param array $descriptions   Array of descriptions in different languages
     * @param array $language       Language for which to retrieve a description
     * 
     * @return string               Vulnerability description
     */
    public static function getDescriptionForLanguage($descriptions, $language=NULL) {

        $language = ($language!=NULL) ? $language : self::getGLPILanguage();

        $descriptions = json_decode($descriptions, true);

        foreach ($descriptions as $vuln_language => $description) {

            if (preg_match("/$vuln_language\_\w\w/i", $language)) {
                
                return $description;
            }
        }

        return $descriptions['en'];
    }

    /**
     * Queries the GLPI database and returns the default language from settings
     * 
     * @since 1.0.0
     * 
     * @return string    GLPI default language
     */
    private static function getGLPILanguage() {

        global $DB;

        /***********************************************************************************************
         * Request GLPI default language from settings
         * 
         *  SELECT value
         *  FROM glpi_configs
         *  WHERE name = language
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'value',
                             'FROM' => 'glpi_configs',
                             'WHERE' => ['name' => 'language']]);

        if ($res->numrows() != 0) {

            $row = $res->current();

            return $row['value'];
        }

        return '';
    }
}

?>