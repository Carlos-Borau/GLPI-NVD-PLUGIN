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
     * @param DBmysqlIterator   $res            Array of descriptions in different languages
     * @param string            $language       Language for which to retrieve a description
     * 
     * @return string           Vulnerability description
     */
    public static function getDescriptionForLanguage($res, $language=NULL) {

        $language = ($language!=NULL) ? $language : PluginNvdDatabaseutils::getGLPILanguage();

        $descriptions = PluginNvdDatabaseutils::pushResToArray($res, 'description', 'language');

        foreach ($descriptions as $vuln_language => $description) {

            if (preg_match("/$vuln_language\_\w\w/i", $language)) {
                
                return $description;
            }
        }

        return $descriptions['en'];
    }

    /**
     * Get vulnerability configuration warning
     * 
     * @since 1.0.0
     * 
     * @param DBmysqlIterator   $res            Array of configurations for a vulnerability
     * @param bool              $isSoftware     Indicates whether to treat the query result as a software or not
     * 
     * @return string           Configuration warning for a vulnerability
     */
    public static function parseConfiguration($res, $isSoftware) {

        $warning_char = mb_chr(0x2757, 'UTF-8');

        if ($res->numrows() > 0) {

            $warning .= 'onclick="alert(\'';

            if ($isSoftware) {

                $row = $res->current();

                $update     = $row['update'];
                $edition    = $row['edition'];
                $target_sw  = $row['target_sw'];
                $target_hw  = $row['target_hw'];

                $warning .= __('Some of the CPE configurations for this software that are associated with this vulnerability\nmay contain some constrains on the following CPE attributes:');
                            
                if (!is_null($update)) { $warning .= '\n - update: ' . $update; }
                if (!is_null($edition)) { $warning .= '\n - sw_edition: ' . $edition; }
                if (!is_null($target_sw)) { $warning .= '\n - target_sw: ' . $target_sw; }
                if (!is_null($target_hw)) { $warning .= '\n - target_hw: ' . $target_hw; }

            } else {

                $warning .= __('Some of the CPE configurations that are associated with this vulnerability\nmay contain some constrains on their CPE attributes.');
            }

            $warning .= '\')">' . $warning_char;

            return $warning;
        }
        
        return '>';
    }
}

?>