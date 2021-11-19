import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { CryptogyService } from '../services/cryptogy.service';

@Component({
  selector: 'app-classic',
  templateUrl: './classic.component.html',
  styleUrls: ['./classic.component.css']
})
export class ClassicComponent implements OnInit {

  randomKeyLoading: boolean = false;
  errorRandomKey: boolean = false;

  encryptLoading: boolean = false;
  errorEncrypt: boolean = false;

  decryptLoading: boolean = false;
  errorDecrypt: boolean = false;

  analyzeLoading: boolean = false;
  errorAnalyze: boolean = false;
  errorAnalyzeMessage: string = "";

  form: FormGroup;
  key: string = "";
  invalidKey: boolean = false;
  constructor(private cryptoService: CryptogyService) { }

  ngOnInit(): void {
    this.form = new FormGroup({
      cipher: new FormControl("shift", { validators: Validators.required }),
      keyLength: new FormControl(5),
      key: new FormControl(null, { validators: Validators.required }),
      cleartext: new FormControl(''),
      ciphertext: new FormControl('')
    });
    this.generate_random_key()

  }

  cryptosystem_change() {
    this.generate_random_key();
  }

  generate_random_key() {
    this.invalidKey = false;
    this.randomKeyLoading = true;
    this.errorRandomKey = false;
    let values = this.form.value;
    this.cryptoService.get_random_key(
      values.cipher,
      values.keyLength
    )
      .subscribe(data => {
        this.form.patchValue({ "key": data })
        this.form.updateValueAndValidity();
        this.randomKeyLoading = false;
      }, err => {
        if(err.error == "Invalid Key"){
          this.invalidKey = true;
        }
        this.errorRandomKey = true;
        this.randomKeyLoading = false;
      })
  }

  encrypt() {

    this.invalidKey = false;
    let values = this.form.value;
    this.encryptLoading = true;
    this.errorEncrypt = false;
    this.cryptoService.encrypt(
      values.key,
      values.cipher,
      values.cleartext, 
      values.keyLength
    ).subscribe(
      data => {
        this.encryptLoading = false;
        this.form.patchValue({"ciphertext": data });
        this.form.updateValueAndValidity();
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
    this.cryptoService.decrypt(
      values.key,
      values.cipher,
      values.ciphertext, 
      values.keyLength
    ).subscribe(
      data => {
        this.decryptLoading = false;
        this.form.patchValue({"cleartext": data});
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

  analyze() { 
    let values = this.form.value;
    this.analyzeLoading = true;
    this.errorAnalyze = false;
    this.cryptoService.analize(
      values.cipher, 
      values.ciphertext
    ).subscribe(
      data => {
        this.analyzeLoading = false;
        this.form.patchValue({"cleartext": data});
        this.form.updateValueAndValidity();
      }, 
      err => {
        this.errorAnalyzeMessage = err.error;
        this.errorAnalyze = true;
        this.analyzeLoading = false;
      }
    )
  }

}
