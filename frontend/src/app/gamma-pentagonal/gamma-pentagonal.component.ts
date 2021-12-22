import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';

@Component({
  selector: 'app-gamma-pentagonal',
  templateUrl: './gamma-pentagonal.component.html',
  styleUrls: ['./gamma-pentagonal.component.css']
})
export class GammaPentagonalComponent implements OnInit {

  constructor() { }

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
      cipher: new FormControl("shift", { validators: Validators.required }),
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

  }

  encrypt(){}

  decrypt(){}

  clearText(){}

  clearCipherText(){}
}
