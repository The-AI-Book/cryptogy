import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { ClassicComponent } from './classic/classic.component';
import { MainComponent } from './main/main.component';

const routes: Routes = [
  {path: "", component: MainComponent}, 
  {path: "classic", component: ClassicComponent}
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
