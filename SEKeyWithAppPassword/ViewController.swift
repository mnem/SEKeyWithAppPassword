//
//  ViewController.swift
//  SEKeyWithAppPassword
//
//  Created by David Wagner on 09/07/2019.
//  Copyright © 2019 David Wagner. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    @IBOutlet var textview: UITextView!
    @IBOutlet var randomSignButton: UIButton!
    @IBOutlet var pairSignButton: UIButton!
    
    var randomKey: KeyHolder?
    var pairKey: KeyHolder?

    @IBAction func handleRandomCreateTapped(_ sender: UIButton) {
        log("Creating key with SecKeyCreateRandom")
        do {
            let tag = "random".data(using: .utf8)!
            let password = "open sesame".data(using: .utf8)!
            randomKey = try createKeyUsingSecKeyCreateRandom(tag: tag, password: password)
            randomSignButton.isEnabled = true
            log("Created!")
        } catch {
            log("Error: \(error)")
        }
    }

    @IBAction func handleRandomSignTapped(_ sender: UIButton) {
        log("Signing with private key from SecKeyCreateRandom")
        do {
            try randomKey!.signAndVerify()
            log("Signed OK!")
        } catch {
            log("Error: \(error)")
        }
    }

    @IBAction func handlePairCreateTapped(_ sender: UIButton) {
        log("Creating key with SecKeyGeneratePair")
        do {
            let tag = "pair".data(using: .utf8)!
            let password = "open sesame open sesame".data(using: .utf8)!
            pairKey = try createKeyUsingSecKeyGeneratePair(tag: tag, password: password)
            pairSignButton.isEnabled = true
            log("Created!")
        } catch {
            log("Error: \(error)")
        }
    }

    @IBAction func handlePairSignTapped(_ sender: UIButton) {
        log("Signing with private key from SecKeyGeneratePair")
        do {
            try pairKey!.signAndVerify()
            log("Signed OK!")
        } catch {
            log("Error: \(error)")
        }
    }

    func log(_ message: String) {
        textview.text.append("➡️ \(message)\n")
    }
}
