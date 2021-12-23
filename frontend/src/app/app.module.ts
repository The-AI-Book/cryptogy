import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule } from '@angular/common/http';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { HeaderComponent } from './header/header.component';
import { FooterComponent } from './footer/footer.component';
import { CryptosystemsComponent } from './cryptosystems/cryptosystems.component';
import { MainComponent } from './main/main.component';
import { ClassicComponent } from './classic/classic.component';
import { PresentationComponent } from './presentation/presentation.component';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { BlockComponent } from './block/block.component';
import { GammaPentagonalComponent } from './gamma-pentagonal/gamma-pentagonal.component';

@NgModule({
  declarations: [
    AppComponent,
    HeaderComponent,
    FooterComponent,
    CryptosystemsComponent,
    MainComponent,
    ClassicComponent,
    PresentationComponent,
    BlockComponent,
    GammaPentagonalComponent,
  ],
  imports: [
    BrowserModule,
    AppRoutingModule, 
    ReactiveFormsModule, 
    HttpClientModule, 
    FormsModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
