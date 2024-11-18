#include <allegro5\allegro.h>
#include <allegro5\allegro_primitives.h>
#include <allegro5/allegro_image.h>
#include <iostream>
#include <iostream>
#include <cstdlib>
#include <time.h>
#include <stdio.h>
#include <windows.h>
#include <vector>
#include <algorithm>
#include <ctime>
#include <stdlib.h>
#include <random>
#include <conio.h>




//Object IDs
enum IDS { PLAYER, BULLET, ENEMY };

//Our Player
struct SpaceShip
{
	int ID;
	int x;
	int y;
	int lives;
	int speed;
	int boundx;
	int boundy;
	int score;
	bool live;
};

struct Bullet
{
	int ID;
	int x;
	int x1;
	int y;
	bool live;
	int speed;
};

struct Comet
{
	int ID;
	int x;
	int y;
	bool live;
	int speed;
	int bt;
	int boundx;
	int boundy;
	bool stop;
};

struct Tetris
{
	int x;
	int y;
	bool live;
	bool stop;
	bool checked;
	int boundx;
	int boundy;
};

struct Lines
{
	std::vector<std::vector <int>> linia;
};

struct LinesBiezaca
{
	std::vector<std::vector <int>> liniabiez;
};

struct Opadanie
{
	std::vector<std::vector <int>> linia;
	bool stop;
};

struct Filtr
{
	std::vector<std::vector <int>> line;
};

//GLOBALS==============================
const int WIDTH = 800;
const int HEIGHT = 600;
const int NUM_BULLETS = 50;
const int NUM_COMETS = 40;
const int STARS = 100;
int sec = 0;
bool imm = 0;
bool bt = 0;


int it = 0;
bool line1 = false;
int l = 0;



enum MODE { SINGLE, LINE, SPREAD, DOUBLE_LINE };
bool mode[4] = { true , false, false, false };

//prototypes
void InitShip(SpaceShip& ship);
void DrawShip(SpaceShip& ship);


void InitBullet(Bullet bullet[], int size);
void DrawBullet(Bullet bullet[], int size);
void FireBullet(Bullet bullet[], int size, SpaceShip& ship);
void FireBullet2(Bullet bullet[], int size, SpaceShip& ship);
void UpdateBulletSingle(Bullet bullet[], int size);
void UpdateBulletLine(Bullet bullet[], int size);
void UpdateBulletSpread(Bullet bullet[], int size);

void InitComet(Comet comets[], int size);
void DrawComet(Comet comets[], int size);
void StartComet(Comet comets[], int size);
void UpdateComet(Comet comets[], int size);



void CollideBullet(Bullet bullet[], int bSize, Comet comets[], int cSize);
void CollideComet(Comet comets[], int cSize, SpaceShip& ship);
void CollideTetris(Tetris block[], int tSize, SpaceShip& ship);

int main(void)
{
	srand(time(NULL));

	//primitive variable
	bool done = false;
	bool redraw = true;
	const int FPS = 60;
	int cntr = 0;
	int licznik = 0;
	int licznik2 = 0;
	int licznik_def = 580;
	int licztab = 0;
	int licz = 0;
	bool row = false;
	bool rozm = false;
	std::vector<std::vector <int>> line_def;

	std::vector<std::vector <int>> line;
	std::vector< std::vector<int>> sprawdz(15, std::vector<int>(2));
	std::vector< std::vector<int>> sprawdz1(15, std::vector<int>(2));

	line_def.push_back({ 20, 580 });
	int wspolrzedna_linii = 20;

	int tab[15][2];
	tab[0][0] = 0;
	tab[0][1] = 580;

	int traf = 0;

	//object variables
	SpaceShip ship;
	Bullet bullets[NUM_BULLETS];
	Comet comets[NUM_COMETS];
	Tetris block[600];
	Lines linie[15];
	LinesBiezaca liniab[15];
	Opadanie opad[15];
	Filtr liniaf[15];
	//Allegro variables
	ALLEGRO_DISPLAY* display = NULL;
	ALLEGRO_EVENT_QUEUE* event_queue = NULL;
	ALLEGRO_TIMER* timer = NULL;

	//Initialization Functions
	if (!al_init())										//initialize Allegro
		return -1;

	display = al_create_display(WIDTH, HEIGHT);			//create our display object

	if (!display)										//test display object
		return -1;

	al_init_primitives_addon();
    al_init_image_addon();
	al_install_keyboard();
	al_install_mouse();
	event_queue = al_create_event_queue();
    background = al_load_bitmap("bg.png");
    if (!background) {
        std::cerr << "Failed to load background image!" << std::endl;
        return -1;
    }

    ship_image = al_load_bitmap("ship.png");
    if (!ship_image) {
        std::cerr << "Failed to load ship image!" << std::endl;
        return -1;
    }

    comet_image = al_load_bitmap("comet.png");
    if (!comet_image) {
        std::cerr << "Failed to load comet image!" << std::endl;
        return -1;
    }
	timer = al_create_timer(1.0 / 60);

	InitShip(ship);
	InitBullet(bullets, NUM_BULLETS);
	InitComet(comets, NUM_COMETS);

	//InitTetris
	for (int i = 0; i < 600; i++)

	{
		block[i].live = false;
		block[i].stop = true;
		block[i].checked = false;
		block[i].boundx = 18;
		block[i].boundy = 18;
	}

	//InitLine

	for (int j = 0; j < 15; j++)


	{
		if (j > 0)licznik_def -= 40;

		//linie[0].linia.push_back({ 20,580 });
		for (int i = 20; i <= 780; i += 40)
		{
			l++;
			if (j == 0) linie[0].linia.push_back({ i,580 });
			else linie[j].linia.push_back({ i,licznik_def });

		}
		sort(linie[0].linia.begin(), linie[0].linia.end());
	}

	//InitFall

	for (int i = 0; i < 15; i++)
	{
		opad[i].linia = linie[i].linia;
		opad[i].stop = true;
	}


	for (int i = 540; i >= 0; i -= 40)
	{
		licztab++;
		tab[licztab][0] = licztab;
		tab[licztab][1] = i;
	}
	//InitSprawdz
	for (int i = 0; i < 15; i++)
		for (int j = 0; j < 2; j++)
			sprawdz[i][j] = tab[i][j];
	//sprawdz.erase(sprawdz.begin());
	sprawdz1 = sprawdz;

	//InitFiltr
	for (int i = 0; i < 15; i++)
		liniaf[i].line = linie[i].linia;
	//liniaf[0].line.erase(liniaf[0].line.begin());

	al_register_event_source(event_queue, al_get_keyboard_event_source());
	al_register_event_source(event_queue, al_get_timer_event_source(timer));
	al_register_event_source(event_queue, al_get_display_event_source(display));
	al_register_event_source(event_queue, al_get_mouse_event_source());

	al_hide_mouse_cursor(display);
	al_start_timer(timer);




	while (!done)
	{
		ALLEGRO_EVENT ev;
		ALLEGRO_MOUSE_STATE state;


		//std::cout << "imm"<<imm <<"   "<<"live" <<ship.live<<"   "<<"sec"<<sec<<std::flush;



		al_get_mouse_state(&state);
		al_wait_for_event(event_queue, &ev);
		sec++;
		//std::cout << sec;
		if (ev.type == ALLEGRO_EVENT_MOUSE_BUTTON_DOWN)
		{

			if (ev.mouse.button == 1)
			{
				if (mode[SINGLE])
				{
					//std::cout << "single";
					FireBullet(bullets, 5, ship);
				}
			}

			else if (ev.mouse.button == 2)
			{
				cntr++;
				if (cntr == 4)

					cntr = 0;
				if (cntr > 0)
				{
					mode[cntr] = true;
					mode[cntr - 1] = false;
				}
				if (cntr == 0)
				{
					mode[0] = true;
					mode[1] = false;
					mode[2] = false;
					mode[3] = false;
				}
				//std::cout << "mode";
			}
			else if (ev.mouse.button == 3) { bt = !bt; }






		}
		//else if (ev.type == ALLEGRO_EVENT_MOUSE_BUTTON_DOWN && ev.mouse.button & 2) for (int i = 0; i < 4; i++) std::cout << mode[i];
		else if (ev.type == ALLEGRO_EVENT_MOUSE_AXES)
		{
			ship.x = ev.mouse.x;

			ship.y = ev.mouse.y;

		}
		if (state.buttons & 1 && (mode[LINE] || mode[SPREAD]))
		{
			//std::cout << "spread";
			FireBullet(bullets, NUM_BULLETS, ship);
		}
		if (state.buttons & 1 && mode[DOUBLE_LINE])
		{
			//std::cout << "line";
			FireBullet2(bullets, NUM_BULLETS, ship);
		}
		//if (ev.type == ALLEGRO_EVENT_MOUSE_BUTTON_DOWN && ev.mouse.button & 2) FireBullet(bullets, 1, ship);
		if (ev.type == ALLEGRO_EVENT_TIMER)
		{
			redraw = true;

			if (mode[SINGLE]) UpdateBulletSingle(bullets, NUM_BULLETS);
			if (mode[LINE] || mode[DOUBLE_LINE]) UpdateBulletLine(bullets, NUM_BULLETS);
			if (mode[SPREAD]) UpdateBulletSpread(bullets, NUM_BULLETS);

			StartComet(comets, NUM_COMETS);
			UpdateComet(comets, NUM_COMETS);
			CollideBullet(bullets, NUM_BULLETS, comets, NUM_COMETS);
			//CollideComet(comets, NUM_COMETS, ship);
			CollideTetris(block, 600, ship);

			//StartTetris
			for (int i = 0; i < 600; i++)
			{
				if (!block[i].live)
				{
					for (int j = 0; j < 40; j++)
						if (comets[j].y + 20 == HEIGHT && comets[j].live)
							//std::cout << "tetris";
						{
							//it++;
							row = true;
							block[i].live = true;

							block[i].x = comets[j].x;
							block[i].y = comets[j].y;
							comets[j].live = false;
							//std::cout << i << " " << j << " ";
							licznik++;
							//std::cout << "!live" << licznik << " ";
							//if (i == 0) liniab[0].liniabiez.push_back({ block[i].x,block[i].y });


							break;


						}
				}
				if (row)
				{

					for (int j = 0; j < 40; j++)
						if (block[i].live && comets[j].x == block[i].x && comets[j].y + 20 == block[i].y - 20 && comets[j].live && comets[j].y > 0)
						{
							//if (j==0) liniab[1].liniabiez.push_back({ block[i].x,block[i].y });
							for (int k = 0; k < 600; k++)
								if (!block[k].live) {
									block[k].live = true;


									block[k].x = comets[j].x;
									block[k].y = comets[j].y;
									//licznik = 0;
									licznik2++;
									std::cout << licznik2 << std::endl;

									//sprawdz czy pierwszy


									break;
								}


							comets[j].live = false;

							//std::cout << "i" << i << " ";
						}
						else if (comets[j].x == block[i].x && comets[j].y + 20 >= block[i].y - 20 && block[i].y == 20)
							comets[j].live = false;
				}

			}

			//PozaEkran
			for (int i = 0; i < 600; i++)
				if (block[i].live && block[i].y <= 5) block[i].live = false;

			//StartLine
			for (int i = 0; i < 600; i++)
				if (block[i].live && !block[i].checked)
					for (int j = 0; j < 15; j++)
						for (int m = 0; m < liniaf[j].line.size(); m++)

							if (tab[j][1] == block[i].y && block[i].x == liniaf[j].line[m][0])
							{
								licz++;
								liniab[j].liniabiez.push_back({ block[i].x,block[i].y });
								sort(liniab[j].liniabiez.begin(), liniab[j].liniabiez.end());

								block[i].checked = true;
								if (liniab[j].liniabiez.size() > 20) rozm = true;
								liniaf[j].line.erase(liniaf[j].line.begin() + m);

							}
			//SprawdzLinie
			for (int j = 0; j < 15; j++)
				if (linie[j].linia == liniab[j].liniabiez)
				{
					opad[j].stop = false;
					//std::cout << "LINE " << j << std::endl;
					liniab[j].liniabiez.erase(liniab[j].liniabiez.begin(), liniab[j].liniabiez.end());
					liniaf[j].line = linie[j].linia;
					for (int l = 0; l < 600; l++)
						if (block[l].live)
							for (int m = 0; m < 20; m++)

								if (block[l].x == linie[j].linia[m][0] && block[l].y == linie[j].linia[j][1])
								{

									liniab[j].liniabiez.erase(liniab[j].liniabiez.begin(), liniab[j].liniabiez.end());
									block[l].live = false;
									block[l].checked = false;



								}


				}

			//BlockAndFall
			for (int i = 0; i < 600; i++)
				if (block[i].stop && block[i].live)
					for (int j = 1; j < 15; j++)
						if (block[i].y == opad[j].linia[j][1] && !opad[j - 1].stop)
						{
							block[i].stop = false;

							//std::cout << "w";


						}
			for (int i = 0; i < 600; i++)
				if (!block[i].stop && block[i].live)
					block[i].y += 5;
			for (int i = 0; i < 15; i++)
				if (liniab[i].liniabiez.size() > 0)
					opad[i].stop = true;
			for (int i = 0; i < 600; i++)
				for (int j = 0; j < 15; j++)
					if (!block[i].stop && block[i].y >= tab[j][1] && block[i].live)
					{
						opad[j].stop = false;
						break;
					}

			for (int i = 0; i < 600; i++)
				if (!block[i].stop && block[i].live && block[i].y + 20 == HEIGHT)
				{
					block[i].stop = true;
					block[i].y = HEIGHT - 20;
					block[i].checked = false;

				}
			//CollideRunningTetris
			for (int i = 0; i < 600; i++)
				if (block[i].stop && block[i].live)
					for (int j = 0; j < 600; j++)
						if (!block[j].stop && block[i].live)
							if (block[i].x == block[j].x && block[j].y + 20 == block[i].y - 20)
							{
								block[j].stop = true;
								block[j].y = block[i].y - 40;
								block[i].checked = false;
								block[j].checked = false;


							}
			//CollideTetris
			for (int i = 0; i < 600; i++)
			{
				if (block[i].live && !imm)
				{
					if (block[i].x - block[i].boundx < ship.x + ship.boundx &&
						block[i].x + block[i].boundx > ship.x - ship.boundx &&
						block[i].y - block[i].boundy < ship.y + 30 &&
						block[i].y + block[i].boundy > ship.y)

					{
						for (int j = 0; j < 15; j++)
							for (int m = 0; m < liniab[j].liniabiez.size(); m++)

								if (tab[j][1] == block[i].y && block[i].x == liniab[j].liniabiez[m][0])
								{

									liniab[j].liniabiez.erase(liniab[j].liniabiez.begin() + m);
									sort(liniab[j].liniabiez.begin(), liniab[j].liniabiez.end());
									liniaf[j].line.push_back({ block[i].x,block[i].y });
									



								}
						ship.lives--;
						block[i].live = false;
						block[i].checked = false;
						ship.live = false;
						//imm = true;

					}


					sec = 0;

				}
			}
		}
		else if (ev.type == ALLEGRO_EVENT_DISPLAY_CLOSE)
		{
			done = true;
		}

		if (imm)
		{
			//std::cout << "imm";
			if (sec % 10 == 0) ship.live = true;
			else ship.live = false;
			if (sec == 120)
			{
				//std::cout << "120";
				ship.live = true;
				imm = false;
				sec = 0;
			}
		}

		if (redraw && al_is_event_queue_empty(event_queue))
		{
			redraw = false;


			DrawShip(ship);
			DrawBullet(bullets, NUM_BULLETS);
			DrawComet(comets, NUM_COMETS, comet_image);

			//DrawTetris
			for (int i = 0; i < 600; i++)
				if (block[i].live && block[i].y - 20 >= 0)
					al_draw_filled_circle(block[i].x, block[i].y, 20, al_map_rgb(255, 255, 255));
				

			al_flip_display();
			al_clear_to_color(al_map_rgb(0, 0, 0));
		}
	}

	al_destroy_event_queue(event_queue);
	al_destroy_timer(timer);
	al_destroy_display(display);						//destroy our display object

	return 0;
}

void InitShip(SpaceShip& ship)
{
	ship.x = 20;
	ship.y = HEIGHT / 2;
	ship.ID = PLAYER;

	ship.lives = 3;
	ship.speed = 7;
	ship.boundx = 6;
	ship.boundy = 7;
	ship.score = 0;
	ship.live = true;
}
void DrawShip(SpaceShip& ship)
{
	//al_draw_filled_rectangle(ship.x, ship.y - 9, ship.x + 10, ship.y - 7, al_map_rgb(255, 0, 0));
	//al_draw_filled_rectangle(ship.x, ship.y + 9, ship.x + 10, ship.y + 7, al_map_rgb(255, 0, 0));

	al_draw_filled_triangle(ship.x, ship.y, ship.x - 20, ship.y + 30, ship.x + 20, ship.y + 30, al_map_rgb(0, 255, 0));
	//al_draw_filled_rectangle(ship.x - 12, ship.y - 2, ship.x + 15, ship.y + 2, al_map_rgb(0, 0, 255));
}
void MoveShipUp(SpaceShip& ship)
{
	ship.y -= ship.speed;
	if (ship.y < 0)
		ship.y = 0;
}
void MoveShipDown(SpaceShip& ship)
{
	ship.y += ship.speed;
	if (ship.y > HEIGHT)
		ship.y = HEIGHT;
}
void MoveShipLeft(SpaceShip& ship)
{
	ship.x -= ship.speed;
	if (ship.x < 0)
		ship.x = 0;
}
void MoveShipRight(SpaceShip& ship)
{
	ship.x += ship.speed;
	if (ship.x > 600)
		ship.x = 600;
}

void InitBullet(Bullet bullet[], int size)
{
	for (int i = 0; i < size; i++)
	{
		bullet[i].ID = BULLET;
		bullet[i].speed = 10;
		bullet[i].live = false;
	}
}
void DrawBullet(Bullet bullet[], int size)
{
	for (int i = 0; i < size; i++)
	{


		if (bullet[i].live)
			if (mode[DOUBLE_LINE])
			{
				al_draw_filled_circle(bullet[i].x + 15, bullet[i].y, 2, al_map_rgb(255, 255, 255));

				al_draw_filled_circle(bullet[i].x - 15, bullet[i].y, 2, al_map_rgb(255, 255, 255));

			}
			else al_draw_filled_circle(bullet[i].x, bullet[i].y, 2, al_map_rgb(255, 255, 255));
	}
}
void FireBullet(Bullet bullet[], int size, SpaceShip& ship)
{
	for (int i = 0; i < size; i++)
	{
		if (!bullet[i].live)
		{
			bullet[i].x = ship.x;
			bullet[i].x1 = ship.x;
			bullet[i].y = ship.y - 17;
			bullet[i].live = true;
			break;
		}
	}
}

void FireBullet2(Bullet bullet[], int size, SpaceShip& ship)
{
	for (int i = 0; i < size; i++)
	{
		if (!bullet[i].live)
		{
			bullet[i].x = ship.x;
			bullet[i].y = ship.y - 17;
			bullet[i].live = true;
			break;
		}
	}
}

void UpdateBulletSpread(Bullet bullet[], int size)
{
	int tempo = 0;
	for (int i = 0; i < size; i++)
	{
		tempo += 5;

		if (bullet[i].live)
		{
			bullet[i].y -= bullet[i].speed + tempo;
			if (bullet[i].y < 0)
				bullet[i].live = false;
		}
	}
}

void UpdateBulletLine(Bullet bullet[], int size)
{

	for (int i = 0; i < size; i++)
	{


		if (bullet[i].live)
		{
			bullet[i].y -= bullet[i].speed + 5;
			if (bullet[i].y < 0)
				bullet[i].live = false;
		}
	}
}

void UpdateBulletSingle(Bullet bullet[], int size)
{

	for (int i = 0; i < size; i++)
	{
		if (bullet[i].live)
		{
			bullet[i].y -= bullet[i].speed;
			if (bullet[i].y < 0)
				bullet[i].live = false;

		}
	}

}

void InitComet(Comet comets[], int size)
{

	for (int i = 0; i < size; i++)
	{
		if (comets[i].y < 0)
		{
			comets[i].ID = ENEMY;
			comets[i].live = false;
			comets[i].speed = 5;
			comets[i].boundx = 18;
			comets[i].boundy = 18;
			comets[i].stop = false;

		}
	}
}
void DrawComet(Comet comets[], int size, ALLEGRO_BITMAP* comet_image) {

	for (int i = 0; i < size; i++)
	{
		if (comets[i].live && comets[i].y > 0)
		{
			al_draw_bitmap(comet_image, comets[i].x - al_get_bitmap_width(comet_image) / 2, comets[i].y - al_get_bitmap_height(comet_image) / 2, 0);
		}
	}
}
void StartComet(Comet comets[], int size)
{
	bool ixy = false;
	int liczx = 0; int liczy = 0;
	int iksy[20]; int ygreki[15];
	iksy[0] = 20; ygreki[0] = -580;
	for (int i = 60; i < 800; i += 40) {

		liczx++;
		iksy[liczx] = i;
		//std::cout << liczx;
	}

	for (int i = -540; i < 0; i += 40) {

		liczy++;
		ygreki[liczy] = i;
		//std::cout << liczy;
	}
	for (int i = 0; i < size; i++)
	{



		if (!comets[i].live && !ixy)
		{

			comets[i].live = true;
			comets[i].x = iksy[rand() % 20];
			comets[i].y = ygreki[rand() % 15];
			for (int j = 0; j < size; j++)
			{
				if (i != j && (comets[j].x == comets[i].x))


				{

					comets[i].live = false;
				}

				if ((i != j && (comets[j].y == comets[i].y)) && comets[i].live && comets[j].live)
					//std::cout << "y";
					comets[i].live = false;
			}

		}



	}



}
void UpdateComet(Comet comets[], int size)
{
	for (int i = 0; i < size; i++)
	{
		if (comets[i].live)
		{
			if (bt == 1) comets[i].y++;
			else
			{
				comets[i].y += comets[i].speed;
				//std::cout << i << " ";
			}

			if (comets[i].y + 20 == HEIGHT)
				comets[i].stop = true;
		}
	}
}

void CollideBullet(Bullet bullet[], int bSize, Comet comets[], int cSize)
{
	for (int i = 0; i < bSize; i++)
	{
		if (bullet[i].live)
		{
			for (int j = 0; j < cSize; j++)
			{
				if (comets[j].live)
				{
					if ((bullet[i].x > (comets[j].x - comets[j].boundx) &&
						bullet[i].x < (comets[j].x + comets[j].boundx) &&
						bullet[i].y >(comets[j].y - comets[j].boundy) &&
						bullet[i].y < (comets[j].y + comets[j].boundy))
						|| mode[DOUBLE_LINE] && (((bullet[i].x + 15 > (comets[j].x - comets[j].boundx) &&
							bullet[i].x + 15 < (comets[j].x + comets[j].boundx) &&
							bullet[i].y > (comets[j].y - comets[j].boundy) &&
							bullet[i].y < (comets[j].y + comets[j].boundy)))) || ((bullet[i].x - 15 > (comets[j].x - comets[j].boundx) &&
								bullet[i].x - 15 < (comets[j].x + comets[j].boundx) &&
								bullet[i].y > (comets[j].y - comets[j].boundy) &&
								bullet[i].y < (comets[j].y + comets[j].boundy))))

					{
						bullet[i].live = false;
						comets[j].live = false;
					}
				}
			}
		}
	}
}

void CollideComet(Comet comets[], int cSize, SpaceShip& ship)
{


	for (int i = 0; i < cSize; i++)
	{
		if (comets[i].live && !imm)
		{
			if (comets[i].x - comets[i].boundx < ship.x + ship.boundx &&
				comets[i].x + comets[i].boundx > ship.x - ship.boundx &&
				comets[i].y - comets[i].boundy < ship.y + 30 &&
				comets[i].y + comets[i].boundy > ship.y)

			{
				ship.lives--;
				comets[i].live = false;
				ship.live = false;
				imm = true;

			}
			else if (comets[i].y > HEIGHT)
			{
				comets[i].live = false;
			}

			sec = 0;

		}
	}


}

void CollideTetris(Tetris block[], int cSize, SpaceShip& ship)
{





}