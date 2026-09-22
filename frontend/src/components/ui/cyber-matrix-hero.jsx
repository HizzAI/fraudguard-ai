"use client";

import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, Code } from 'lucide-react';

// A utility function for class names
const cn = (...classes) => classes.filter(Boolean).join(' ');

// The main hero component
const CyberMatrixHero = ({ onDeploy }) => {
    const gridRef = useRef(null);
    const [isClient, setIsClient] = useState(false);

    useEffect(() => {
        // This ensures the code only runs on the client, avoiding SSR issues.
        setIsClient(true);
    }, []);

    useEffect(() => {
        if (!isClient || !gridRef.current) return;

        const grid = gridRef.current;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789<>/?;:"[]{}\\|!@#$%^&*()_+-=';
        let columns = 0;
        let rows = 0;
        
        const createTile = (index) => {
            const tile = document.createElement('div');
            tile.classList.add('tile');
            
            tile.onclick = e => {
                const target = e.target;
                target.textContent = chars[Math.floor(Math.random() * chars.length)];
                target.classList.add('glitch');
                setTimeout(() => target.classList.remove('glitch'), 200);
            };

            return tile;
        }

        const createTiles = (quantity) => {
            Array.from(Array(quantity)).map((_, index) => {
                grid.appendChild(createTile(index));
            });
        }

        const createGrid = () => {
            grid.innerHTML = '';
            
            const size = 60; // Made tiles smaller for a denser grid
            columns = Math.floor(window.innerWidth / size);
            rows = Math.floor(window.innerHeight / size);
            
            grid.style.setProperty('--columns', columns);
            grid.style.setProperty('--rows', rows);
            
            createTiles(columns * rows);

            // Set initial characters
            for(const tile of grid.children) {
                tile.textContent = chars[Math.floor(Math.random() * chars.length)];
            }
        }

        const handleMouseMove = e => {
            const mouseX = e.clientX;
            const mouseY = e.clientY;
            const radius = window.innerWidth / 4;

            for(const tile of grid.children) {
                const rect = tile.getBoundingClientRect();
                const tileX = rect.left + rect.width / 2;
                const tileY = rect.top + rect.height / 2;

                const distance = Math.sqrt(
                    Math.pow(mouseX - tileX, 2) + Math.pow(mouseY - tileY, 2)
                );

                const intensity = Math.max(0, 1 - distance / radius);
                
                tile.style.setProperty('--intensity', intensity);
            }
        };

        window.addEventListener('resize', createGrid);
        window.addEventListener('mousemove', handleMouseMove);
        
        createGrid();

        return () => {
            window.removeEventListener('resize', createGrid);
            window.removeEventListener('mousemove', handleMouseMove);
        };

    }, [isClient]);

    const fadeUpVariants = {
        hidden: { opacity: 0, y: 20 },
        visible: (i) => ({
            opacity: 1,
            y: 0,
            transition: {
                delay: i * 0.2 + 0.5,
                duration: 0.8,
                ease: "easeInOut",
            },
        }),
    };

    return (
        <div className="relative h-[60vh] min-h-[500px] w-full bg-[#0b0f19] flex flex-col items-center justify-center overflow-hidden rounded-xl border border-slate-800">
            {/* Animated Grid Background */}
            <div ref={gridRef} id="tiles"></div>
            
            <style>{`
                #tiles {
                    --intensity: 0;
                    display: grid;
                    grid-template-columns: repeat(var(--columns), 1fr);
                    grid-template-rows: repeat(var(--rows), 1fr);
                    width: 100%;
                    height: 100%;
                    position: absolute;
                    top: 0;
                    left: 0;
                }
                .tile {
                    position: relative;
                    cursor: pointer;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    font-family: 'Courier New', Courier, monospace;
                    font-size: 1.2rem;
                    
                    /* Use CSS variable for dynamic styling */
                    opacity: calc(0.1 + var(--intensity) * 0.5);
                    color: hsl(210, 100%, calc(50% + var(--intensity) * 50%)); /* Changed from green to blue for SOC feel */
                    text-shadow: 0 0 calc(var(--intensity) * 15px) hsl(210, 100%, 50%);
                    transform: scale(calc(1 + var(--intensity) * 0.2));
                    transition: color 0.2s ease, text-shadow 0.2s ease, transform 0.2s ease;
                }
                .tile.glitch {
                    animation: glitch-anim 0.2s ease;
                }
                @keyframes glitch-anim {
                    0% { transform: scale(1); color: #0088ff; }
                    50% { transform: scale(1.2); color: #fff; text-shadow: 0 0 10px #fff; }
                    100% { transform: scale(1); color: #0088ff; }
                }
            `}</style>

            {/* Overlay HTML Content */}
            <div className="relative z-10 text-center p-8 bg-[#0b0f19]/80 backdrop-blur-md rounded-2xl border border-slate-700/50 shadow-2xl">
                <motion.div
                    custom={0}
                    variants={fadeUpVariants}
                    initial="hidden"
                    animate="visible"
                    className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 mb-6"
                >
                    <Code className="h-4 w-4 text-blue-400" />
                    <span className="text-sm font-medium text-blue-200">
                        SIH 2026 Prototype
                    </span>
                </motion.div>

                <motion.h1
                    custom={1}
                    variants={fadeUpVariants}
                    initial="hidden"
                    animate="visible"
                    className="text-5xl md:text-6xl font-bold tracking-tighter mb-4 bg-clip-text text-transparent bg-gradient-to-b from-white to-slate-400"
                >
                    FraudGuard AI
                </motion.h1>

                <motion.p
                    custom={2}
                    variants={fadeUpVariants}
                    initial="hidden"
                    animate="visible"
                    className="max-w-2xl mx-auto text-lg text-slate-400 mb-8"
                >
                    Advanced Android Malware Static Analysis & Risk Assessment.
                </motion.p>

                <motion.div
                    custom={3}
                    variants={fadeUpVariants}
                    initial="hidden"
                    animate="visible"
                >
                    <button 
                        onClick={onDeploy}
                        className="px-8 py-4 bg-white text-black font-semibold rounded-lg shadow-[0_0_20px_rgba(255,255,255,0.3)] hover:bg-slate-200 transition-all duration-300 flex items-center gap-2 mx-auto"
                    >
                        Begin Investigation
                        <ArrowRight className="h-5 w-5" />
                    </button>
                </motion.div>
            </div>
        </div>
    );
};

export default CyberMatrixHero;
