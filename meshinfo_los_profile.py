import json
import utils
import os
import rasterio
import numpy as np
import matplotlib
import logging
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from scipy.spatial import distance
from geopy.distance import geodesic
import logging
import time
import io
import base64
import pandas as pd
import atexit


class LOSProfile():
    def __init__(self, nodes={}, node=None, config=None, cache=None):
        self.nodes = nodes
        self.node = node
        self.datasets = []
        self.max_distance = int(config['los']['max_distance']) if config and 'los' in config else 5000  # Default to 5000 if not set
        self.cache_duration = int(config['los']['cache_duration']) if config and 'los' in config else 43200  # Default to 43200 if not set

        self.cache = cache  # Store the cache object

        directory = "srtm_data"
        try:
            for filename in os.listdir(directory):
                if filename.endswith(".tif"):
                    filepath = os.path.join(directory, filename)
                    dataset = rasterio.open(filepath)
                    self.datasets.append(dataset)
        except FileNotFoundError as e:
            logging.warning("No SRTM data found in directory: %s", directory)
            pass
        atexit.register(self.close_datasets)

    def close_datasets(self):
        """Close all open rasterio datasets."""
        for ds in self.datasets:
            if not ds.closed:
                ds.close()
        self.datasets = []

    def calculate_distance_between_coords(self, coord1, coord2):
        lat1, lon1 = coord1
        lat2, lon2 = coord2
        return geodesic((lat1, lon1), (lat2, lon2)).meters

    def read_elevation_from_tifb(self, lat, lon):
        """
        Reads elevation data from preloaded .tif files for a specific
        coordinate.
        """
        for dataset in self.datasets:
            if dataset.bounds.left <= lon <= dataset.bounds.right \
                    and dataset.bounds.bottom <= lat <= dataset.bounds.top:
                # Rasterio expects (lat, lon) as (y, x)
                row, col = dataset.index(lon, lat)

                # Read only the required pixel
                elevation = dataset.read(
                    1,
                    window=((row, row+1), (col, col+1))
                )[0, 0]

                # Check for NoData values
                if elevation == dataset.nodata or np.isnan(elevation):
                    logging.warning(
                        f"Invalid elevation data at ({lat}, {lon})"
                    )
                    return []

                return elevation

        logging.debug(
            f"No elevation data found for coordinates ({lat}, {lon})"
        )
        return []

    def read_elevation_from_tif(self, lat, lon):
        """
        Reads elevation data from preloaded .tif files for a specific
        coordinate using efficient windowed reading.
        """
        for dataset in self.datasets:
            # Check if the coordinate is within the bounds of this dataset
            if dataset.bounds.left <= lon <= dataset.bounds.right \
                    and dataset.bounds.bottom <= lat <= dataset.bounds.top:
                try:
                    # Get the row and column index for the coordinate
                    row, col = dataset.index(lon, lat)

                    # Read only the required pixel using a window
                    # Ensure indices are within dataset dimensions
                    if 0 <= row < dataset.height and 0 <= col < dataset.width:
                        # Read a 1x1 window at the specified row, col
                        elevation = dataset.read(
                            1,
                            window=((row, row + 1), (col, col + 1))
                        )[0, 0] # Extract the single value

                        # Check for NoData values (important!)
                        # Use dataset.nodatavals tuple if multiple bands exist, otherwise dataset.nodata
                        nodata_val = dataset.nodata
                        # Handle potential float nodata comparison issues
                        if nodata_val is not None and np.isclose(float(elevation), float(nodata_val)):
                            logging.warning(
                                f"NoData value found at ({lat}, {lon}) in {dataset.name}"
                            )
                            return None # Return None or a specific indicator for NoData
                        elif np.isnan(elevation):
                             logging.warning(
                                f"NaN value found at ({lat}, {lon}) in {dataset.name}"
                            )
                             return None # Return None or indicator for NaN

                        return elevation # Return the valid elevation
                    else:
                        logging.warning(f"Calculated index ({row}, {col}) out of bounds for dataset {dataset.name}")
                        return None # Index out of bounds

                except Exception as e:
                    logging.error(f"Error reading elevation for ({lat}, {lon}) from {dataset.name}: {e}")
                    return None # Error during read

        # If coordinate wasn't found in any dataset bounds
        # logging.debug( # Changed to debug as this can be noisy
        #     f"Coordinate ({lat}, {lon}) not within bounds of any loaded dataset."
        # )
        return None # Coordinate not found in any dataset

    def generate_los_profile(self, coord1, coord2, resolution=100):
        """
        Generates a line-of-sight profile between two coordinates using SRTM
        data and altitude.
        Uses geodesic distance instead of Euclidean distance.
        """
        lat1, lon1, alt1 = coord1
        lat2, lon2, alt2 = coord2

        # Interpolate points along the line
        latitudes = np.linspace(lat1, lat2, resolution)
        longitudes = np.linspace(lon1, lon2, resolution)

        elevations = []
        valid_points = 0
        for lat, lon in zip(latitudes, longitudes):
            elevation = self.read_elevation_from_tif(lat, lon)
            # Handle cases where elevation might be None (NoData, NaN, out of bounds)
            if elevation is not None:
                elevations.append(elevation)
                valid_points += 1
            else:
                # Decide how to handle missing points:
                # Option 1: Append a placeholder like NaN (if plotting handles it)
                elevations.append(np.nan)
                # Option 2: Skip the point (distances array would need adjustment)
                # Option 3: Interpolate (more complex)

        # Check if enough valid points were found
        if valid_points < 2: # Need at least start and end for a line
             logging.warning(f"Could not retrieve enough elevation points between {coord1[:2]} and {coord2[:2]}. Skipping profile.")
             return None, None # Indicate failure

        # Compute accurate geodesic distances from start point
        distances = [
            geodesic((lat1, lon1), (lat, lon)).meters for lat, lon in
            zip(latitudes, longitudes)
        ]

        profile = [elev if not np.isnan(elev) else 0 for elev in elevations] # Replace NaN with 0 for now, adjust if needed
        # Add altitude to elevation for the final profile
        # Ensure profile has elements before accessing indices
        if profile:
            # Use provided altitude if available, otherwise use terrain elevation
            profile[0] = alt1 if alt1 is not None else (profile[0] if not np.isnan(profile[0]) else 0)
            profile[-1] = alt2 if alt2 is not None else (profile[-1] if not np.isnan(profile[-1]) else 0)

        # Simple linear interpolation for NaN values in the middle
        profile_series = pd.Series(profile)
        profile_series.interpolate(method='linear', inplace=True)
        profile = profile_series.tolist()

        return distances, profile

    def plot_los_profile(self, distances, profile, label):
        # Create a unique cache key based on the input parameters
        cache_key = f"los_profile_{label}_{hash(tuple(distances))}_{hash(tuple(profile))}"

        # Check if the image is already cached
        cached_image = self.cache.get(cache_key)  # Use self.cache
        if cached_image:
            return cached_image  # Return the cached image if it exists

        # --- Font Setup ---
        # Attempt to load Symbola font
        try:
            symbola_font_path = '/usr/share/fonts/truetype/ancient-scripts/Symbola_hint.ttf'
            symbol_font = FontProperties(fname=symbola_font_path)
        except FileNotFoundError:
            logging.warning(f"Could not find font file at specified path: {symbola_font_path}. Symbols/Emojis may not render correctly.")
            symbol_font = None  # Fallback to default
        except ValueError:
            logging.warning("Error loading font from specified path, even if found. Symbols/Emojis may not render correctly.")
            symbol_font = None  # Fallback to default

        fig = plt.figure(figsize=(10, 6))
        ax = fig.gca()
        ax.set_facecolor("cyan")
        plt.margins(x=0, y=0, tight=True)

        # Check if profile has valid data
        if not profile or len(profile) < 2:
            logging.warning(f"Profile data is invalid or too short for plotting label: {label}")
            plt.close(fig)
            return None

        start_alt = profile[0]
        end_alt = profile[-1]

        if np.isnan(start_alt) or np.isnan(end_alt):
            logging.warning(f"Cannot plot direct LOS line due to NaN start/end altitude for label: {label}")
            direct_line = np.full(len(profile), np.nan)
        else:
            direct_line = np.linspace(start_alt, end_alt, len(profile))

        # Plot the terrain profile
        if not np.isnan(profile).all():
            plt.fill_between(distances, profile, color="brown", alpha=1.0, label="Terrain Profile")
            plt.plot(distances, profile, color="brown", label="Profile Outline")
        else:
            logging.warning(f"Terrain profile contains only NaN values for label: {label}")

        # Plot the direct LOS line
        if not np.isnan(direct_line).all():
            plt.plot(distances, direct_line, color="green", linestyle="dashed", linewidth=2, label="Direct LOS Line")

        # --- Apply FontProperties (using symbol_font) ---
        plt.xlabel("Distance (meters)", fontproperties=symbol_font)
        plt.ylabel("Elevation + Altitude (meters)", fontproperties=symbol_font)
        plt.title(f"{label}", fontproperties=symbol_font)
        plt.legend(prop=symbol_font)

        buffer = io.BytesIO()
        try:
            plt.savefig(buffer, format="png", bbox_inches="tight")
            buffer.seek(0)
            img_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

            # Cache the rendered image for 12 hours (43,200 seconds)
            self.cache.set(cache_key, img_base64, timeout=self.cache_duration)

        except Exception as e:
            logging.error(f"Error saving plot to buffer for label {label}: {e}")
            img_base64 = None
        finally:
            plt.close(fig)

        return img_base64
    
    def get_profiles(self):
        profiles = {}
        hexid = utils.convert_node_id_from_int_to_hex(self.node)
        if not self.datasets:
            return profiles
        if hexid not in self.nodes:
            return profiles
        mynode = self.nodes[hexid]
        if "position" not in mynode:
            return profiles
        if "latitude" not in mynode["position"]:
            return profiles
        mylat = mynode["position"]["latitude"]
        mylon = mynode["position"]["longitude"]
        myalt = mynode["position"]["altitude"]
        c = 0
        for node_id in self.nodes:
            node = self.nodes[node_id]
            if node_id == hexid:
                continue
            if "position" not in node:
                continue
            try:
                lat = node["position"]["latitude"]
                lon = node["position"]["longitude"]
                alt = node["position"]["altitude"]
                dist = self.calculate_distance_between_coords(
                    (mylat, mylon),
                    (lat, lon)
                )

                if (dist and dist < self.max_distance):
                    coord1 = (mylat, mylon, myalt)
                    coord2 = (lat, lon, alt)
                    # output_path = f"altitude_{c}.png" # Not used, can remove
                    c += 1
                    lname1 = mynode["long_name"]
                    sname1 = mynode["short_name"]
                    lname2 = node["long_name"]
                    sname2 = node["short_name"]
                    # --- Ensure original label is used ---
                    label = f"{lname1} ({sname1}) <=> {lname2} ({sname2})"
                    # ------------------------------------
                    distances, profile = self.generate_los_profile(
                        coord1,
                        coord2
                    )
                    # Check if profile generation was successful
                    if distances is not None and profile is not None:
                        # Pass the original label with emojis
                        image = self.plot_los_profile(
                            distances,
                            profile,
                            label
                        )
                        # Check if plotting was successful
                        if image is not None:
                            profiles[node_id] = {
                                "image": image,
                                "distance": dist
                            }
                        else:
                             logging.warning(f"Failed to generate plot for profile: {label}")
                    else:
                         logging.warning(f"Failed to generate profile data between {coord1[:2]} and {coord2[:2]}")

            except KeyError as e:
                pass
                # logging.warning(f"Missing key 'position' or coordinates for node {node_id} or {hexid}: {e}")
            except TypeError as e:
                pass
        return profiles

    def __del__(self):
        self.close_datasets()

if __name__ == "__main__":
    from meshdata import MeshData
    md = MeshData()
    nodes = md.get_nodes()
    lp = LOSProfile(nodes, 862243760)
    print(lp.get_profiles())
