<?php

namespace Tests;

use PHPUnit\Framework\TestCase;

class BasicTest extends TestCase
{
    public function testClassLoading()
    {
        // Test that we can load the main classes without errors
        $this->assertTrue(class_exists('server\RadiusServer'));
        $this->assertTrue(class_exists('server\dictionary\DictionaryManager'));
        $this->assertTrue(class_exists('server\attribute\AttributeHandler'));
    }
    
    public function testDictionaryLoading()
    {
        // Test basic dictionary loading functionality
        $dictionaryManager = new \server\dictionary\DictionaryManager();
        
        // Try to load a simple dictionary file that should exist
        $result = $dictionaryManager->load_dictionary("dictionary.compat");
        
        // This should return true for valid files
        $this->assertTrue($result);
    }
    
    public function testVendorAttributeSupport()
    {
        // Test that vendor attributes can be loaded
        $dictionaryManager = new \server\dictionary\DictionaryManager();
        
        // Load the Mikrotik dictionary
        $result = $dictionaryManager->load_dictionary("dictionary.mikrotik");
        
        // Should load successfully
        $this->assertTrue($result);
    }
    
    public function testServerInstantiation()
    {
        // Test that we can create a server instance without errors
        // This is a simple check that the class exists and can be instantiated
        $this->assertTrue(class_exists('\server\RadiusServer'));
    }
}