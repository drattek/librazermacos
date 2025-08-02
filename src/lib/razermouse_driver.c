
/**
 * Universal Razer Mouse Driver for macOS
 * Supports all Razer mouse models with feature detection
 * Based on OpenRazer reverse engineering and device JSON configurations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDLib.h>

#include "../include/razercommon.h"
#include "../include/razerchromacommon.h"

// =================== DEVICE FEATURE FLAGS ===================
// Comprehensive feature detection based on device capabilities

#define RAZER_MOUSE_FEAT_DPI                 (1ULL << 0)   // Basic DPI control
#define RAZER_MOUSE_FEAT_DPI_STAGES          (1ULL << 1)   // Multi-stage DPI
#define RAZER_MOUSE_FEAT_AVAILABLE_DPI       (1ULL << 2)   // Fixed DPI list
#define RAZER_MOUSE_FEAT_POLL_RATE           (1ULL << 3)   // Polling rate control
#define RAZER_MOUSE_FEAT_BATTERY             (1ULL << 4)   // Wireless battery
#define RAZER_MOUSE_FEAT_CHARGING            (1ULL << 5)   // Charging status
#define RAZER_MOUSE_FEAT_DOCK                (1ULL << 6)   // Dock support
#define RAZER_MOUSE_FEAT_HYPERFLUX           (1ULL << 7)   // HyperFlux charging

// LED Features
#define RAZER_MOUSE_FEAT_LOGO_LED            (1ULL << 8)   // Logo lighting
#define RAZER_MOUSE_FEAT_SCROLL_LED          (1ULL << 9)   // Scroll wheel LED
#define RAZER_MOUSE_FEAT_LEFT_LED            (1ULL << 10)  // Left side LED
#define RAZER_MOUSE_FEAT_RIGHT_LED           (1ULL << 11)  // Right side LED
#define RAZER_MOUSE_FEAT_UNDERGLOW           (1ULL << 12)  // Underglow LEDs

// Matrix/Advanced lighting
#define RAZER_MOUSE_FEAT_LOGO_MATRIX         (1ULL << 13)  // Logo matrix effects
#define RAZER_MOUSE_FEAT_SCROLL_MATRIX       (1ULL << 14)  // Scroll matrix effects
#define RAZER_MOUSE_FEAT_LEFT_MATRIX         (1ULL << 15)  // Left matrix effects
#define RAZER_MOUSE_FEAT_RIGHT_MATRIX        (1ULL << 16)  // Right matrix effects

// Legacy effects (older models)
#define RAZER_MOUSE_FEAT_OLD_EFFECTS         (1ULL << 17)  // Static/Blinking/Pulsate
#define RAZER_MOUSE_FEAT_BREATHING           (1ULL << 18)  // Breathing effect
#define RAZER_MOUSE_FEAT_SPECTRUM            (1ULL << 19)  // Spectrum cycling
#define RAZER_MOUSE_FEAT_REACTIVE            (1ULL << 20)  // Reactive effects
#define RAZER_MOUSE_FEAT_WAVE                (1ULL << 21)  // Wave effects

// Advanced features
#define RAZER_MOUSE_FEAT_PROFILE             (1ULL << 22)  // Profile switching
#define RAZER_MOUSE_FEAT_CALIBRATION         (1ULL << 23)  // Surface calibration
#define RAZER_MOUSE_FEAT_LIFT_HEIGHT         (1ULL << 24)  // Lift-off distance
#define RAZER_MOUSE_FEAT_ANGLE_SNAPPING      (1ULL << 25)  // Angle snapping

// =================== DEVICE DATABASE ===================

typedef struct {
    uint16_t product_id;
    const char *name;
    uint64_t features;           // Feature bitmask
    uint16_t max_dpi;           // Maximum DPI
    uint8_t led_count;          // Number of LED zones
    uint8_t matrix_rows;        // Matrix dimensions (if applicable)
    uint8_t matrix_cols;
    const uint16_t *available_dpi; // Fixed DPI list (if applicable)
    uint8_t dpi_count;
    const char *series;         // Mouse series for grouping
} razer_mouse_device_t;

// Available DPI arrays for devices with fixed DPI
static const uint16_t abyssus_dpi[] = {800, 1600, 3200};
static const uint16_t viper_mini_dpi[] = {400, 800, 1600, 3200, 6400, 8500};
static const uint16_t basilisk_essential_dpi[] = {400, 800, 1600, 2400, 4000, 6400};
static const uint16_t orochi_dpi[] = {800, 1600, 3200, 6400, 8500};

// Comprehensive device database covering all major Razer mouse models
static const razer_mouse_device_t razer_mouse_devices[] = {
    // ===== DEATHADDER SERIES =====
    {0x0007, "Razer DeathAdder 3.5G", 
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_LOGO_LED | RAZER_MOUSE_FEAT_OLD_EFFECTS,
     3500, 1, 0, 0, NULL, 0, "DeathAdder"},
    
    {0x001E, "Razer DeathAdder 2013",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_LED | RAZER_MOUSE_FEAT_SCROLL_LED,
     6400, 2, 0, 0, NULL, 0, "DeathAdder"},
    
    {0x0043, "Razer DeathAdder Chroma",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_BREATHING | RAZER_MOUSE_FEAT_SPECTRUM | RAZER_MOUSE_FEAT_REACTIVE,
     10000, 2, 0, 0, NULL, 0, "DeathAdder"},
     
    {0x0070, "Razer DeathAdder V2",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_POLL_RATE | RAZER_MOUSE_FEAT_PROFILE,
     20000, 2, 0, 0, NULL, 0, "DeathAdder"},

    {0x0084, "Razer DeathAdder V2 Mini",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX |
     RAZER_MOUSE_FEAT_POLL_RATE | RAZER_MOUSE_FEAT_PROFILE,
     8500, 1, 0, 0, NULL, 0, "DeathAdder"},

    // ===== BASILISK SERIES =====  
    {0x0064, "Razer Basilisk",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_POLL_RATE,
     16000, 2, 0, 0, NULL, 0, "Basilisk"},
     
    {0x0085, "Razer Basilisk V2",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_POLL_RATE | RAZER_MOUSE_FEAT_PROFILE,
     20000, 2, 0, 0, NULL, 0, "Basilisk"},
     
    {0x00B9, "Razer Basilisk V3 X HyperSpeed", // From protocol analysis
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_SCROLL_LED | 
     RAZER_MOUSE_FEAT_BATTERY | RAZER_MOUSE_FEAT_CHARGING,
     26000, 1, 0, 0, NULL, 0, "Basilisk"},

    {0x0079, "Razer Basilisk Essential",
     RAZER_MOUSE_FEAT_AVAILABLE_DPI | RAZER_MOUSE_FEAT_LOGO_LED,
     6400, 1, 0, 0, basilisk_essential_dpi, sizeof(basilisk_essential_dpi)/sizeof(uint16_t), "Basilisk"},

    {0x007D, "Razer Basilisk Ultimate",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_BATTERY | RAZER_MOUSE_FEAT_CHARGING | RAZER_MOUSE_FEAT_DOCK | RAZER_MOUSE_FEAT_PROFILE,
     20000, 2, 0, 0, NULL, 0, "Basilisk"},

    // ===== VIPER SERIES =====
    {0x007A, "Razer Viper",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX |
     RAZER_MOUSE_FEAT_POLL_RATE | RAZER_MOUSE_FEAT_PROFILE,
     16000, 1, 0, 0, NULL, 0, "Viper"},
     
    {0x007B, "Razer Viper Mini",
     RAZER_MOUSE_FEAT_AVAILABLE_DPI | RAZER_MOUSE_FEAT_LOGO_LED,
     8500, 1, 0, 0, viper_mini_dpi, sizeof(viper_mini_dpi)/sizeof(uint16_t), "Viper"},

    {0x008C, "Razer Viper 8KHz",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX |
     RAZER_MOUSE_FEAT_POLL_RATE | RAZER_MOUSE_FEAT_PROFILE,
     20000, 1, 0, 0, NULL, 0, "Viper"},

    {0x007C, "Razer Viper Ultimate",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX |
     RAZER_MOUSE_FEAT_BATTERY | RAZER_MOUSE_FEAT_CHARGING | RAZER_MOUSE_FEAT_DOCK | RAZER_MOUSE_FEAT_PROFILE,
     20000, 1, 0, 0, NULL, 0, "Viper"},

    // ===== NAGA SERIES =====
    {0x0053, "Razer Naga Chroma",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_LEFT_MATRIX | RAZER_MOUSE_FEAT_RIGHT_MATRIX | RAZER_MOUSE_FEAT_UNDERGLOW,
     16000, 4, 0, 0, NULL, 0, "Naga"},

    {0x0067, "Razer Naga Trinity",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_LEFT_MATRIX | RAZER_MOUSE_FEAT_PROFILE,
     16000, 3, 0, 0, NULL, 0, "Naga"},

    {0x008D, "Razer Naga Pro",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_LEFT_MATRIX | RAZER_MOUSE_FEAT_BATTERY | RAZER_MOUSE_FEAT_CHARGING | RAZER_MOUSE_FEAT_PROFILE,
     20000, 3, 0, 0, NULL, 0, "Naga"},

    // ===== ABYSSUS SERIES =====
    {0x005A, "Razer Abyssus Essential",
     RAZER_MOUSE_FEAT_AVAILABLE_DPI | RAZER_MOUSE_FEAT_LOGO_LED,
     7200, 1, 0, 0, abyssus_dpi, sizeof(abyssus_dpi)/sizeof(uint16_t), "Abyssus"},

    {0x005B, "Razer Abyssus V2",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_LOGO_LED | RAZER_MOUSE_FEAT_SCROLL_LED,
     5000, 2, 0, 0, NULL, 0, "Abyssus"},

    // ===== MAMBA SERIES =====
    {0x0073, "Razer Mamba Elite",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_LEFT_MATRIX | RAZER_MOUSE_FEAT_RIGHT_MATRIX | RAZER_MOUSE_FEAT_POLL_RATE,
     16000, 4, 0, 0, NULL, 0, "Mamba"},

    {0x0044, "Razer Mamba Chroma",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_BATTERY | RAZER_MOUSE_FEAT_CHARGING,
     16000, 2, 0, 0, NULL, 0, "Mamba"},

    // ===== OROCHI SERIES =====
    {0x0039, "Razer Orochi 2013",
     RAZER_MOUSE_FEAT_AVAILABLE_DPI | RAZER_MOUSE_FEAT_BATTERY,
     8200, 0, 0, 0, orochi_dpi, sizeof(orochi_dpi)/sizeof(uint16_t), "Orochi"},

    {0x008E, "Razer Orochi V2",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_BATTERY,
     18000, 0, 0, 0, NULL, 0, "Orochi"},

    // ===== LANCEHEAD SERIES =====
    {0x0071, "Razer Lancehead Wired",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_LEFT_MATRIX | RAZER_MOUSE_FEAT_RIGHT_MATRIX,
     16000, 4, 0, 0, NULL, 0, "Lancehead"},

    {0x0072, "Razer Lancehead Wireless",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX |
     RAZER_MOUSE_FEAT_LEFT_MATRIX | RAZER_MOUSE_FEAT_RIGHT_MATRIX | RAZER_MOUSE_FEAT_BATTERY | RAZER_MOUSE_FEAT_CHARGING,
     16000, 4, 0, 0, NULL, 0, "Lancehead"},

    // ===== DIAMONDBACK SERIES =====
    {0x004C, "Razer Diamondback Chroma",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_DPI_STAGES | RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX,
     16000, 2, 0, 0, NULL, 0, "Diamondback"},

    // ===== TAIPAN SERIES =====
    {0x0034, "Razer Taipan",
     RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_LOGO_LED | RAZER_MOUSE_FEAT_SCROLL_LED,
     8200, 2, 0, 0, NULL, 0, "Taipan"},

    // Add more devices as needed...
};

#define RAZER_MOUSE_DEVICE_COUNT (sizeof(razer_mouse_devices) / sizeof(razer_mouse_device_t))

// =================== DEVICE STATE MANAGEMENT ===================

typedef struct {
    IOHIDDeviceRef device_ref;
    const razer_mouse_device_t *device_info;
    pthread_mutex_t lock;
    
    // Current state
    uint16_t current_dpi_x;
    uint16_t current_dpi_y;
    uint8_t current_dpi_stage;
    uint8_t battery_level;
    bool is_charging;
    uint8_t brightness_logo;
    uint8_t brightness_scroll;
    
    // Capabilities cache
    bool supports_wireless;
    bool supports_dock;
    bool supports_matrix;
    
} razer_mouse_state_t;

// Global device registry
static razer_mouse_state_t *g_mouse_devices[16] = {0};
static int g_device_count = 0;
static pthread_mutex_t g_registry_lock = PTHREAD_MUTEX_INITIALIZER;

// =================== DEVICE DETECTION & INITIALIZATION ===================

static const razer_mouse_device_t *razer_mouse_get_device_info(uint16_t product_id)
{
    for (int i = 0; i < RAZER_MOUSE_DEVICE_COUNT; i++) {
        if (razer_mouse_devices[i].product_id == product_id) {
            return &razer_mouse_devices[i];
        }
    }
    return NULL;
}

static void razer_mouse_device_matched(void *context, IOReturn result, void *sender, IOHIDDeviceRef device)
{
    CFNumberRef vendor_id_ref = IOHIDDeviceGetProperty(device, CFSTR(kIOHIDVendorIDKey));
    CFNumberRef product_id_ref = IOHIDDeviceGetProperty(device, CFSTR(kIOHIDProductIDKey));
    
    if (!vendor_id_ref || !product_id_ref) return;
    
    int vendor_id, product_id;
    CFNumberGetValue(vendor_id_ref, kCFNumberIntType, &vendor_id);
    CFNumberGetValue(product_id_ref, kCFNumberIntType, &product_id);
    
    if (vendor_id != RAZER_USB_VID) return;
    
    const razer_mouse_device_t *device_info = razer_mouse_get_device_info(product_id);
    if (!device_info) {
        printf("[MOUSE] Unknown Razer mouse: PID 0x%04X\n", product_id);
        return;
    }
    
    // Allocate device state
    razer_mouse_state_t *mouse_state = calloc(1, sizeof(razer_mouse_state_t));
    if (!mouse_state) return;
    
    mouse_state->device_ref = device;
    mouse_state->device_info = device_info;
    pthread_mutex_init(&mouse_state->lock, NULL);
    
    // Initialize capabilities
    mouse_state->supports_wireless = (device_info->features & RAZER_MOUSE_FEAT_BATTERY) != 0;
    mouse_state->supports_dock = (device_info->features & RAZER_MOUSE_FEAT_DOCK) != 0;
    mouse_state->supports_matrix = (device_info->features & (RAZER_MOUSE_FEAT_LOGO_MATRIX | RAZER_MOUSE_FEAT_SCROLL_MATRIX)) != 0;
    
    // Set default values
    mouse_state->current_dpi_x = 800;
    mouse_state->current_dpi_y = 800;
    mouse_state->current_dpi_stage = 1;
    mouse_state->brightness_logo = 255;
    mouse_state->brightness_scroll = 255;
    
    // Register device
    pthread_mutex_lock(&g_registry_lock);
    if (g_device_count < 16) {
        g_mouse_devices[g_device_count++] = mouse_state;
        printf("[MOUSE] Registered: %s (Features: 0x%016llX)\n", 
               device_info->name, device_info->features);
    }
    pthread_mutex_unlock(&g_registry_lock);
}

static void razer_mouse_device_removed(void *context, IOReturn result, void *sender, IOHIDDeviceRef device)
{
    pthread_mutex_lock(&g_registry_lock);
    
    for (int i = 0; i < g_device_count; i++) {
        if (g_mouse_devices[i] && g_mouse_devices[i]->device_ref == device) {
            printf("[MOUSE] Removed: %s\n", g_mouse_devices[i]->device_info->name);
            
            pthread_mutex_destroy(&g_mouse_devices[i]->lock);
            free(g_mouse_devices[i]);
            
            // Shift array
            for (int j = i; j < g_device_count - 1; j++) {
                g_mouse_devices[j] = g_mouse_devices[j + 1];
            }
            g_device_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_registry_lock);
}

// =================== CORE FUNCTIONALITY ===================

// Universal DPI control
int razer_mouse_set_dpi_xy(razer_mouse_state_t *mouse, uint16_t dpi_x, uint16_t dpi_y)
{
    if (!mouse || !mouse->device_info) return -1;
    
    const razer_mouse_device_t *info = mouse->device_info;
    
    // Feature check
    if (!(info->features & (RAZER_MOUSE_FEAT_DPI | RAZER_MOUSE_FEAT_AVAILABLE_DPI))) {
        return -1; // Not supported
    }
    
    // Validate DPI against device capabilities
    if (info->features & RAZER_MOUSE_FEAT_AVAILABLE_DPI) {
        // Check against available DPI list
        bool valid = false;
        for (int i = 0; i < info->dpi_count; i++) {
            if (info->available_dpi[i] == dpi_x) {
                valid = true;
                break;
            }
        }
        if (!valid) return -2; // Invalid DPI
        dpi_y = 0; // Single-axis DPI
    } else {
        // Check against max DPI
        if (dpi_x > info->max_dpi || dpi_y > info->max_dpi) {
            return -2; // DPI too high
        }
    }
    
    pthread_mutex_lock(&mouse->lock);
    
    struct razer_report report = {0};
    
    // Build DPI command based on device type
    if (info->features & RAZER_MOUSE_FEAT_AVAILABLE_DPI) {
        // Single-axis DPI devices (like Viper Mini)
        report = razer_chroma_mouse_set_dpi_single(VARSTORE, dpi_x);
    } else {
        // Dual-axis DPI devices
        report = razer_chroma_mouse_set_dpi_xy(VARSTORE, dpi_x, dpi_y);
    }
    
    int result = razer_send_payload(mouse->device_ref, &report);
    
    if (result == 0) {
        mouse->current_dpi_x = dpi_x;
        mouse->current_dpi_y = dpi_y;
    }
    
    pthread_mutex_unlock(&mouse->lock);
    return result;
}

// Battery level for wireless mice
int razer_mouse_get_battery_level(razer_mouse_state_t *mouse, uint8_t *level, bool *is_charging)
{
    if (!mouse || !level || !is_charging) return -1;
    
    if (!(mouse->device_info->features & RAZER_MOUSE_FEAT_BATTERY)) {
        return -1; // Not a wireless mouse
    }
    
    pthread_mutex_lock(&mouse->lock);
    
    struct razer_report report = razer_chroma_misc_get_battery_level();
    struct razer_report response = {0};
    
    int result = razer_send_payload(mouse->device_ref, &report);
    if (result == 0) {
        mouse->battery_level = response.arguments[1];
        mouse->is_charging = response.arguments[2] != 0;
        
        *level = mouse->battery_level;
        *is_charging = mouse->is_charging;
    }
    
    pthread_mutex_unlock(&mouse->lock);
    return result;
}

// Universal LED brightness control
int razer_mouse_set_brightness(razer_mouse_state_t *mouse, uint8_t brightness, razer_led_id led_id)
{
    if (!mouse) return -1;
    
    const razer_mouse_device_t *info = mouse->device_info;
    uint64_t required_feature = 0;
    
    switch (led_id) {
        case LOGO_LED:
            required_feature = RAZER_MOUSE_FEAT_LOGO_LED | RAZER_MOUSE_FEAT_LOGO_MATRIX;
            break;
        case SCROLL_LED:
            required_feature = RAZER_MOUSE_FEAT_SCROLL_LED | RAZER_MOUSE_FEAT_SCROLL_MATRIX;
            break;
        default:
            return -1;
    }
    
    if (!(info->features & required_feature)) {
        return -1; // LED not supported
    }
    
    pthread_mutex_lock(&mouse->lock);
    
    struct razer_report report;
    
    if (info->features & RAZER_MOUSE_FEAT_BATTERY) {
        // Wireless mice use different brightness commands
        report = razer_chroma_mouse_set_wireless_brightness(VARSTORE, led_id, brightness);
    } else {
        // Wired mice
        report = razer_chroma_mouse_set_brightness(VARSTORE, led_id, brightness);
    }
    
    int result = razer_send_payload(mouse->device_ref, &report);
    
    if (result == 0) {
        if (led_id == LOGO_LED) {
            mouse->brightness_logo = brightness;
        } else if (led_id == SCROLL_LED) {
            mouse->brightness_scroll = brightness;
        }
    }
    
    pthread_mutex_unlock(&mouse->lock);
    return result;
}

// Matrix effects for advanced mice
int razer_mouse_set_matrix_effect_static(razer_mouse_state_t *mouse, razer_led_id led_id, 
                                        uint8_t red, uint8_t green, uint8_t blue)
{
    if (!mouse) return -1;
    
    const razer_mouse_device_t *info = mouse->device_info;
    uint64_t required_feature = 0;
    
    switch (led_id) {
        case LOGO_LED:
            required_feature = RAZER_MOUSE_FEAT_LOGO_MATRIX;
            break;
        case SCROLL_LED:
            required_feature = RAZER_MOUSE_FEAT_SCROLL_MATRIX;
            break;
        case LEFT_LED:
            required_feature = RAZER_MOUSE_FEAT_LEFT_MATRIX;
            break;
        case RIGHT_LED:
            required_feature = RAZER_MOUSE_FEAT_RIGHT_MATRIX;
            break;
        default:
            return -1;
    }
    
    if (!(info->features & required_feature)) {
        return -1; // Matrix not supported
    }
    
    pthread_mutex_lock(&mouse->lock);
    
    struct razer_rgb color = {red, green, blue};
    struct razer_report report = razer_chroma_mouse_led_matrix_set_static(VARSTORE, led_id, &color);
    
    int result = razer_send_payload(mouse->device_ref, &report);
    
    pthread_mutex_unlock(&mouse->lock);
    return result;
}

// Legacy LED effects for older mice
int razer_mouse_set_logo_led_effect(razer_mouse_state_t *mouse, uint8_t effect_id)
{
    if (!mouse) return -1;
    
    if (!(mouse->device_info->features & RAZER_MOUSE_FEAT_OLD_EFFECTS)) {
        return -1; // Legacy effects not supported
    }
    
    pthread_mutex_lock(&mouse->lock);
    
    struct razer_report report = {0};
    
    switch (effect_id) {
        case 0: // Static
            report = razer_chroma_mouse_led_set_static(VARSTORE, LOGO_LED);
            break;
        case 1: // Blinking 
            report = razer_chroma_mouse_led_set_blinking(VARSTORE, LOGO_LED);
            break;
        case 2: // Pulsate
            report = razer_chroma_mouse_led_set_pulsate(VARSTORE, LOGO_LED);
            break;
        case 3: // Scroll (if supported)
            if (mouse->device_info->features & RAZER_MOUSE_FEAT_SCROLL_LED) {
                report = razer_chroma_mouse_led_set_scroll(VARSTORE, LOGO_LED);
            } else {
                pthread_mutex_unlock(&mouse->lock);
                return -1;
            }
            break;
        default:
            pthread_mutex_unlock(&mouse->lock);
            return -1;
    }
    
    int result = razer_send_payload(mouse->device_ref, &report);
    
    pthread_mutex_unlock(&mouse->lock);
    return result;
}

// =================== PUBLIC API FUNCTIONS ===================

// Initialize the mouse driver
int razer_mouse_driver_init(void)
{
    printf("[MOUSE] Universal Razer Mouse Driver v2.0 - macOS\n");
    printf("[MOUSE] Supporting %zu mouse models across all series\n", RAZER_MOUSE_DEVICE_COUNT);
    
    // Create HID manager
    IOHIDManagerRef hid_manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    if (!hid_manager) {
        printf("[MOUSE] Failed to create HID manager\n");
        return -1;
    }
    
    // Set up device matching for all Razer mice
    CFMutableDictionaryRef matching_dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    CFNumberRef vendor_id = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &(int){RAZER_USB_VID});
    CFDictionarySetValue(matching_dict, CFSTR(kIOHIDVendorIDKey), vendor_id);
    CFRelease(vendor_id);
    
    IOHIDManagerSetDeviceMatching(hid_manager, matching_dict);
    CFRelease(matching_dict);
    
    // Register callbacks
    IOHIDManagerRegisterDeviceMatchingCallback(hid_manager, razer_mouse_device_matched, NULL);
    IOHIDManagerRegisterDeviceRemovalCallback(hid_manager, razer_mouse_device_removed, NULL);
    
    // Schedule with run loop
    IOHIDManagerScheduleWithRunLoop(hid_manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    
    // Open HID manager
    IOReturn ret = IOHIDManagerOpen(hid_manager, kIOHIDOptionsTypeNone);
    if (ret != kIOReturnSuccess) {
        printf("[MOUSE] Failed to open HID manager: 0x%08x\n", ret);
        CFRelease(hid_manager);
        return -1;
    }
    
    printf("[MOUSE] Driver initialized successfully\n");
    return 0;
}

// Get device count
int razer_mouse_get_device_count(void)
{
    pthread_mutex_lock(&g_registry_lock);
    int count = g_device_count;
    pthread_mutex_unlock(&g_registry_lock);
    return count;
}

// Get device info by index
const razer_mouse_device_t *razer_mouse_get_device_by_index(int index)
{
    if (index < 0 || index >= g_device_count) return NULL;
    
    pthread_mutex_lock(&g_registry_lock);
    const razer_mouse_device_t *info = g_mouse_devices[index] ? g_mouse_devices[index]->device_info : NULL;
    pthread_mutex_unlock(&g_registry_lock);
    
    return info;
}

// API wrapper functions
int razer_mouse_api_set_dpi(int device_index, uint16_t dpi_x, uint16_t dpi_y)
{
    if (device_index < 0 || device_index >= g_device_count) return -1;
    
    pthread_mutex_lock(&g_registry_lock);
    razer_mouse_state_t *mouse = g_mouse_devices[device_index];
    pthread_mutex_unlock(&g_registry_lock);
    
    return razer_mouse_set_dpi_xy(mouse, dpi_x, dpi_y);
}

int razer_mouse_api_get_battery(int device_index, uint8_t *level, bool *is_charging)
{
    if (device_index < 0 || device_index >= g_device_count) return -1;
    
    pthread_mutex_lock(&g_registry_lock);
    razer_mouse_state_t *mouse = g_mouse_devices[device_index];
    pthread_mutex_unlock(&g_registry_lock);
    
    return razer_mouse_get_battery_level(mouse, level, is_charging);
}

int razer_mouse_api_set_logo_brightness(int device_index, uint8_t brightness)
{
    if (device_index < 0 || device_index >= g_device_count) return -1;
    
    pthread_mutex_lock(&g_registry_lock);
    razer_mouse_state_t *mouse = g_mouse_devices[device_index];
    pthread_mutex_unlock(&g_registry_lock);
    
    return razer_mouse_set_brightness(mouse, brightness, LOGO_LED);
}

int razer_mouse_api_set_logo_static_color(int device_index, uint8_t red, uint8_t green, uint8_t blue)
{
    if (device_index < 0 || device_index >= g_device_count) return -1;
    
    pthread_mutex_lock(&g_registry_lock);
    razer_mouse_state_t *mouse = g_mouse_devices[device_index];
    pthread_mutex_unlock(&g_registry_lock);
    
    return razer_mouse_set_matrix_effect_static(mouse, LOGO_LED, red, green, blue);
}

// Cleanup function
void razer_mouse_driver_cleanup(void)
{
    pthread_mutex_lock(&g_registry_lock);
    
    for (int i = 0; i < g_device_count; i++) {
        if (g_mouse_devices[i]) {
            pthread_mutex_destroy(&g_mouse_devices[i]->lock);
            free(g_mouse_devices[i]);
            g_mouse_devices[i] = NULL;
        }
    }
    g_device_count = 0;
    
    pthread_mutex_unlock(&g_registry_lock);
    
    printf("[MOUSE] Driver cleanup complete\n");
}

// Print supported devices (for debugging)
void razer_mouse_print_supported_devices(void)
{
    printf("\n[MOUSE] Supported Devices (%zu total):\n", RAZER_MOUSE_DEVICE_COUNT);
    printf("========================================\n");
    
    const char *current_series = "";
    for (int i = 0; i < RAZER_MOUSE_DEVICE_COUNT; i++) {
        const razer_mouse_device_t *device = &razer_mouse_devices[i];
        
        if (strcmp(current_series, device->series) != 0) {
            printf("\n=== %s Series ===\n", device->series);
            current_series = device->series;
        }
        
        printf("  0x%04X: %s (Max DPI: %d)\n", 
               device->product_id, device->name, device->max_dpi);
        
        // Print key features
        printf("    Features: ");
        if (device->features & RAZER_MOUSE_FEAT_DPI) printf("DPI ");
        if (device->features & RAZER_MOUSE_FEAT_BATTERY) printf("Wireless ");
        if (device->features & RAZER_MOUSE_FEAT_LOGO_MATRIX) printf("RGB-Matrix ");
        if (device->features & RAZER_MOUSE_FEAT_OLD_EFFECTS) printf("Legacy-LED ");
        if (device->features & RAZER_MOUSE_FEAT_PROFILE) printf("Profiles ");
        printf("\n");
    }
    printf("\n");
}
