<?php

/**
 * The slice of W3 Total Cache's API that WebDecoy_Page_Cache calls, held in
 * memory: Dispatcher::config(), Config get/set, Util_Admin::config_save() and
 * the Root_Environment rule rewrite. Test-only.
 */

namespace W3TC;

class Config
{
    /** @var array<string,mixed> What is "on disk". */
    public static $stored = [];

    /** @var array<string,mixed> */
    public $data;

    public function __construct($blog_id = null)
    {
        unset($blog_id);
        $this->data = self::$stored;
    }

    public function get_array($key, $default = [])
    {
        return $this->data[$key] ?? $default;
    }

    public function get_boolean($key)
    {
        return !empty($this->data[$key]);
    }

    public function set($key, $value)
    {
        $this->data[$key] = $value;
    }
}

class Root_Environment
{
    /** @var int */
    public static $fixes = 0;

    public function fix_in_wpadmin($config)
    {
        unset($config);
        self::$fixes++;
    }
}

class Dispatcher
{
    public static function config()
    {
        return new Config();
    }

    public static function component($name)
    {
        unset($name);
        return new Root_Environment();
    }
}

class Util_Admin
{
    /** @var bool */
    public static $fail = false;
    /** @var int */
    public static $saves = 0;

    public static function config_save($current, $new)
    {
        unset($current);
        if (self::$fail) {
            throw new \Exception('cannot write config');
        }
        self::$saves++;
        Config::$stored = $new->data;
    }
}
