#include <allegro5/allegro.h>
#include <allegro5/allegro_image.h>
#include <allegro5/allegro_primitives.h>
#include <iostream>
#include <cstdlib>
#include <time.h>
#include <vector>

// Object IDs
enum IDS { PLAYER, BULLET, ENEMY };

// Our Player
struct SpaceShip {
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

// Comet
struct Comet {
    int ID;
    int x;
    int y;
    bool live;
    int speed;
    int boundx;
    int boundy;
};

// GLOBALS
const int WIDTH = 800;
const int HEIGHT = 600;
const int NUM_COMETS = 40;

// Prototypes
void InitShip(SpaceShip& ship);
void DrawShip(SpaceShip& ship, ALLEGRO_BITMAP* ship_image);
void InitComet(Comet comets[], int size);
void DrawComet(Comet comets[], int size, ALLEGRO_BITMAP* comet_image);

int main(void) {
    srand(time(NULL));

    // Allegro variables
    ALLEGRO_DISPLAY* display = NULL;
    ALLEGRO_EVENT_QUEUE* event_queue = NULL;
    ALLEGRO_TIMER* timer = NULL;
    ALLEGRO_BITMAP* background = NULL;
    ALLEGRO_BITMAP* ship_image = NULL;
    ALLEGRO_BITMAP* comet_image = NULL;
    bool done = false;
    bool redraw = true;
    const int FPS = 60;
    int background_y = 0;

    SpaceShip ship;
    Comet comets[NUM_COMETS];

    // Initialize Allegro
    if (!al_init()) {
        std::cerr << "Failed to initialize Allegro!" << std::endl;
        return -1;
    }

    // Create display
    display = al_create_display(WIDTH, HEIGHT);
    if (!display) {
        std::cerr << "Failed to create display!" << std::endl;
        return -1;
    }

    // Initialize add-ons
    al_init_primitives_addon();
    al_init_image_addon();
    al_install_keyboard();

    // Load resources
    background = al_load_bitmap("background.png");
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

    // Initialize game objects
    InitShip(ship);
    InitComet(comets, NUM_COMETS);

    // Create timer and event queue
    event_queue = al_create_event_queue();
    timer = al_create_timer(1.0 / FPS);

    al_register_event_source(event_queue, al_get_keyboard_event_source());
    al_register_event_source(event_queue, al_get_timer_event_source(timer));
    al_register_event_source(event_queue, al_get_display_event_source(display));

    al_start_timer(timer);

    // Game loop
    while (!done) {
        ALLEGRO_EVENT ev;
        al_wait_for_event(event_queue, &ev);

        if (ev.type == ALLEGRO_EVENT_TIMER) {
            redraw = true;

            // Scroll the background
            background_y += 2;
            if (background_y >= HEIGHT) {
                background_y = 0;
            }
        }
        else if (ev.type == ALLEGRO_EVENT_DISPLAY_CLOSE) {
            done = true;
        }

        if (redraw && al_is_event_queue_empty(event_queue)) {
            redraw = false;

            // Draw the scrolling background
            al_draw_bitmap(background, 0, background_y, 0);
            al_draw_bitmap(background, 0, background_y - HEIGHT, 0);

            // Draw the spaceship
            DrawShip(ship, ship_image);

            // Draw comets
            DrawComet(comets, NUM_COMETS, comet_image);

            // Flip display
            al_flip_display();
        }
    }

    // Clean up
    al_destroy_bitmap(background);
    al_destroy_bitmap(ship_image);
    al_destroy_bitmap(comet_image);
    al_destroy_timer(timer);
    al_destroy_display(display);
    al_destroy_event_queue(event_queue);

    return 0;
}

// Initialize the spaceship
void InitShip(SpaceShip& ship) {
    ship.x = WIDTH / 2;
    ship.y = HEIGHT - 50;
    ship.lives = 3;
    ship.speed = 7;
    ship.boundx = 18;
    ship.boundy = 18;
    ship.ID = PLAYER;
    ship.live = true;
}

// Draw the spaceship using the ship image
void DrawShip(SpaceShip& ship, ALLEGRO_BITMAP* ship_image) {
    if (ship.live) {
        al_draw_bitmap(ship_image, ship.x - al_get_bitmap_width(ship_image) / 2, ship.y - al_get_bitmap_height(ship_image) / 2, 0);
    }
}

// Initialize comets
void InitComet(Comet comets[], int size) {
    for (int i = 0; i < size; i++) {
        comets[i].live = false;
        comets[i].speed = rand() % 5 + 1;
        comets[i].x = rand() % WIDTH;
        comets[i].y = 0;
        comets[i].boundx = 18;
        comets[i].boundy = 18;
        comets[i].ID = ENEMY;
    }
}

// Draw comets using the comet image
void DrawComet(Comet comets[], int size, ALLEGRO_BITMAP* comet_image) {
    for (int i = 0; i < size; i++) {
        if (comets[i].live) {
            al_draw_bitmap(comet_image, comets[i].x - al_get_bitmap_width(comet_image) / 2, comets[i].y - al_get_bitmap_height(comet_image) / 2, 0);
        }
    }
}
