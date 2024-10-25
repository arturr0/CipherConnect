#include <allegro5\allegro.h>
#include <allegro5\allegro_primitives.h>
#include <iostream>


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

int main(void)
{
	//primitive variable
	bool done = false;
	bool redraw = true;
	const int FPS = 60;
	int cntr = 0;


	//object variables
	SpaceShip ship;
	Bullet bullets[NUM_BULLETS];
	Comet comets[NUM_COMETS];

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
	al_install_keyboard();
	al_install_mouse();
	event_queue = al_create_event_queue();
	timer = al_create_timer(1.0 / 60);

	InitShip(ship);
	InitBullet(bullets, NUM_BULLETS);
	InitComet(comets, NUM_COMETS);

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
					std::cout << "single";
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
				std::cout << "mode";
			}
			else if (ev.mouse.button == 3) { bt = !bt; std::cout << "kolka" << bt; }






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
			CollideComet(comets, NUM_COMETS, ship);
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


			if (ship.live) DrawShip(ship);
			DrawBullet(bullets, NUM_BULLETS);
			DrawComet(comets, NUM_COMETS);

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
	if (ship.x > 300)
		ship.x = 300;
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
		comets[i].ID = ENEMY;
		comets[i].live = false;
		comets[i].speed = 5;
		comets[i].boundx = 18;
		comets[i].boundy = 18;
	}
}
void DrawComet(Comet comets[], int size)
{
	for (int i = 0; i < size; i++)
	{
		if (comets[i].live)
		{
			al_draw_filled_circle(comets[i].x, comets[i].y, 20, al_map_rgb(255, 0, 0));
		}
	}
}
void StartComet(Comet comets[], int size)
{
	for (int i = 0; i < size; i++)
	{
		if (!comets[i].live)
		{
			if (rand() % 250 == 0)
			{
				comets[i].live = true;
				comets[i].x = 30 + rand() % WIDTH;
				comets[i].y = 0;

				break;
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
			else comets[i].y += comets[i].speed;

			if (comets[i].y > HEIGHT)
				comets[i].live = false;
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
				comets[i].y - comets[i].boundy < ship.y + ship.boundy &&
				comets[i].y + comets[i].boundy > ship.y - ship.boundy)
			{
				ship.lives--;
				comets[i].live = false;
				ship.live = false;
				imm = true;



			}
			else if (comets[i].x < 0)
			{
				comets[i].live = false;
				ship.lives--;
			}

			sec = 0;

		}
	}


}
