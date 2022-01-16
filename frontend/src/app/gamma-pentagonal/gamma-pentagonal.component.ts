import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { CryptogyService } from '../services/cryptogy.service';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-gamma-pentagonal',
  templateUrl: './gamma-pentagonal.component.html',
  styleUrls: ['./gamma-pentagonal.component.css']
})
export class GammaPentagonalComponent implements OnInit {

  constructor(private cryptoService: CryptogyService) { }

  form: FormGroup;
  randomKeyLoading: boolean = false;
  errorRandomKey: boolean = false;
  invalidKey: boolean = false;
  encryptLoading: boolean = false;
  errorEncrypt: boolean  = false;
  decryptLoading: boolean = false;
  errorDecrypt: boolean = false;

  ngOnInit(): void {
    this.form = new FormGroup({
      cipher: new FormControl("gamma-pentagonal", { validators: Validators.required }),
      keyLength: new FormControl(5),
      key: new FormControl(null, { validators: Validators.required }),
      cleartext: new FormControl(''),
      ciphertext: new FormControl(''),
      keyStream: new FormControl(''), 
      numPartitions: new FormControl(2, {validators: Validators.required}), 
      file: new FormControl(null)
    });
  }

  generate_random_key(){
    this.invalidKey = false;
    this.randomKeyLoading = true;
    this.errorRandomKey = false;
    let values = this.form.value;
    this.cryptoService.get_random_key(
      values.cipher,
      values.keyLength, 
      values.numPartitions
    ).subscribe(
      data => {
        //console.log(data);
        this.form.patchValue({"key": data["random_key"] })
        this.form.updateValueAndValidity();
        this.randomKeyLoading = false;
      },
      err => {
        //console.log(err);
        if(err.error == "Invalid Key"){
          this.invalidKey = true;
        }
        this.errorRandomKey = true;
        this.randomKeyLoading = false;
    })
  }

  encrypt(){
    
    this.invalidKey = false;
    let values = this.form.value;
    this.encryptLoading = true;
    this.errorEncrypt = false;

    let cleartext = values.cleartext;

    this.cryptoService.encrypt(
      values.key,
      values.cipher,
      cleartext, 
      values.keyLength, 
      values.numPartitions, 
      "", 
      "", 
      ""
    ).subscribe(
      data => {
        this.encryptLoading = false;
        this.form.patchValue({"ciphertext": data["ciphertext"] });
        this.form.updateValueAndValidity();
        if(data["key_stream"]){
          this.form.patchValue({"keyStream": data["key_stream"]});
          this.form.updateValueAndValidity();
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
      values.keyLength, 
      values.keyStream, 
      values.numPartitions, 
      "", 
      "", 
      ""
    ).subscribe(
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
