/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.luis.cert.test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 *
 * @author luis
 */
class KeyPair {
    
    public final PublicKey publicKey;
    public final PrivateKey privateKey;
    public final Certificate certificate;

    public KeyPair(PublicKey publicKey, PrivateKey privateKey, Certificate certificate) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.certificate = certificate;
    }
    
}
