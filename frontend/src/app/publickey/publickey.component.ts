import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { CryptogyService } from '../services/cryptogy.service';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-publickey',
  templateUrl: './publickey.component.html',
  styleUrls: ['./publickey.component.css']
})
export class PublickeyComponent implements OnInit {

  randomKeyLoading: boolean = false;
  errorRandomKey: boolean = false;

  encryptLoading: boolean = false;
  errorEncrypt: boolean = false;

  decryptLoading: boolean = false;
  errorDecrypt: boolean = false;

  form: FormGroup;
  key: string = "";
  invalidKey: boolean = false;
  constructor(private cryptoService: CryptogyService, private domSanitizer: DomSanitizer) { }

  ngOnInit(): void {
    this.form = new FormGroup({
      cipher: new FormControl("rsa", { validators: Validators.required }),
      key: new FormControl(null, { validators: Validators.required }),
      cleartext: new FormControl(''),
      ciphertext: new FormControl('')
    });
    this.generate_random_key();

    this.form.get("key").valueChanges.subscribe(val => {
       this.form.updateValueAndValidity();
    });

  }

  cryptosystem_change() {
    this.generate_random_key();
    this.form.patchValue({"cleartext": ""});
    this.form.patchValue({"ciphertext": ""}); 
    this.form.updateValueAndValidity();
  }

  generate_random_key() {
    this.invalidKey = false;
    this.randomKeyLoading = true;
    this.errorRandomKey = false;
    let values = this.form.value;
    this.cryptoService.get_random_key(
      values.cipher, 
      values.keyLength, 
      "0"
    )
      .subscribe(data => {
        //console.log(data);
        this.form.patchValue({"key": data["random_key"] })
        this.form.updateValueAndValidity();
        this.randomKeyLoading = false;
      }, err => {
        //console.log(err);
        if(err.error == "Invalid Key"){
          this.invalidKey = true;
        }
        this.errorRandomKey = true;
        this.randomKeyLoading = false;
      })
  }

  encrypt() {
    let values = this.form.value;
    
    //if(values.cipher == "aes"){
    //  if(values.key.length != parseInt(this.form.value.keyLength)){
    //      this.invalidKey = true;
    //      return;
    //  }
    //}

    this.form.updateValueAndValidity();

    this.invalidKey = false;
    this.encryptLoading = true;
    this.errorEncrypt = false;
    let cleartext = values.cleartext;
    this.invalidKey = false;

  
    this.cryptoService.encrypt(
      values.key,
      values.cipher,
      cleartext, 
      "0",
      "0",
      "0",
      "0",
      "0",
      values.numberP,
      values.numberQ,
      values.numberE,
    ).subscribe(
      data => {
        this.encryptLoading = false;
        this.form.patchValue({"ciphertext": data["ciphertext"] });
        this.form.updateValueAndValidity();
        if(data["permutation"]){
          this.form.patchValue({"initialPermutation": data["permutation"]});
          this.form.updateValueAndValidity();
        }
        if(data["schedule"]){
          this.form.patchValue({"schedule": data["schedule"]});
          this.form.updateValueAndValidity();
        }
        if(data["numberP"]){
          console.log("numero primo P");
          if(data["numberP"] != this.form.value.numberP){
              console.log("change")
              console.log(this.form.value.numberP);
              console.log(data["numberP"]);
              this.form.patchValue({"numberP": data["numberP"]});
              this.form.updateValueAndValidity();
          }
        }
      }, err => {
        if(err.error == "Invalid Key"){
          this.invalidKey = true;
        }
        this.encryptLoading = false;
        this.errorEncrypt = true;
      }
    )
  }

  decrypt() {

    let values = this.form.value;
    this.decryptLoading = true;
    this.errorDecrypt = false;
    let ciphertext = values.ciphertext;

    this.cryptoService.decrypt(
      values.key,
      values.cipher,
      ciphertext, 
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      values.numberP,
      values.numberQ,
      values.numberE,
    )
    .subscribe(
      data => {
        this.decryptLoading = false;
        this.form.patchValue({"cleartext": data["cleartext"]});
        this.form.updateValueAndValidity();
      }, err => {
        this.decryptLoading = false;
        this.errorDecrypt = true;
      }
    )
  }

  clearText(){
    this.form.patchValue({"cleartext":""})
    this.form.updateValueAndValidity();
  }

  clearCipherText(){
    this.form.patchValue({"ciphertext":""})
    this.form.updateValueAndValidity();
  }
}

